use crate::common::{AppResult, TS_PACKET_SIZE};
use crate::crypto::{parse_key_spec, AesBlockEncryptor};
use crate::hevc::decrypt_pes_normal;
use crate::ts::{
    extract_packet_block_key, packet_info, parse_pat, parse_pmt_streams_map,
    parse_pmt_video_pids, parse_sdt_and_set_iv, PSIAssembler,
};
use crate::ui::ProgressUi;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

const SYNC: u8 = 0x47;
const PID_PAT: u16 = 0x0000;
const PID_SDT: u16 = 0x0011;

struct PESHeaderChunk {
    header_bytes: Vec<u8>,
    header_size: usize,
}

fn flush_pes_fn(
    pes_buf: &mut Vec<u8>,
    pes_headers: &mut Vec<PESHeaderChunk>,
    iv_snap_for_pes: &mut Option<[u8; 16]>,
    last_pid: &mut u16,
    state_ready: bool,
    stream_types: &HashMap<u16, u8>,
    encryptor: &AesBlockEncryptor,
    writer: &mut BufWriter<File>,
) -> AppResult<()> {
    if pes_buf.is_empty() || pes_headers.is_empty() || !state_ready {
        pes_buf.clear();
        pes_headers.clear();
        *iv_snap_for_pes = None;
        *last_pid = 0xFFFF;
        return Ok(());
    }

    let sid_prev = if pes_buf.len() > 3 { pes_buf[3] } else { 0xE1 };
    if (sid_prev & 0xF0 == 0xE0 || sid_prev == 0xE0) && pes_buf.len() > 8 && iv_snap_for_pes.is_some() {
        let stream_type = stream_types.get(last_pid).copied().unwrap_or(0x24);
        let decrypted = decrypt_pes_normal(
            pes_buf,
            stream_type,
            encryptor,
            &iv_snap_for_pes.unwrap(),
        );
        *pes_buf = decrypted;
    }

    let mut pes_remain = pes_buf.len();
    let mut pes_pos = 0usize;

    for (i, h) in pes_headers.iter().enumerate() {
        let payload_cap = TS_PACKET_SIZE.saturating_sub(h.header_size);

        if pes_remain == 0 {
            writer.write_all(&h.header_bytes)?;
            let padding = vec![0xff; payload_cap];
            writer.write_all(&padding)?;
        } else if pes_remain < payload_cap {
            if i == pes_headers.len() - 1 {
                let mut hdr = h.header_bytes.clone();
                let stuffing_needed = payload_cap - pes_remain;
                let afc = (hdr[3] >> 4) & 0x03;

                if afc == 1 {
                    hdr[3] = (hdr[3] & 0x0F) | 0x30;
                    if stuffing_needed == 1 {
                        hdr.push(0x00);
                    } else {
                        hdr.push((stuffing_needed - 1) as u8);
                        hdr.push(0x00);
                        if stuffing_needed > 2 {
                            hdr.extend(std::iter::repeat(0xff).take(stuffing_needed - 2));
                        }
                    }
                } else if afc == 3 {
                    let af_len = hdr[4] as usize;
                    let extra = stuffing_needed;
                    hdr[4] = (af_len + extra) as u8;
                    let mut new_hdr = Vec::with_capacity(hdr.len() + extra);
                    new_hdr.extend_from_slice(&hdr[..5 + af_len]);
                    new_hdr.extend(std::iter::repeat(0xff).take(extra));
                    new_hdr.extend_from_slice(&hdr[5 + af_len..]);
                    hdr = new_hdr;
                }

                writer.write_all(&hdr)?;
                writer.write_all(&pes_buf[pes_pos..pes_pos + pes_remain])?;
                pes_pos += pes_remain;
                pes_remain = 0;
            } else {
                writer.write_all(&h.header_bytes)?;
                writer.write_all(&pes_buf[pes_pos..pes_pos + pes_remain])?;
                pes_pos += pes_remain;
                pes_remain = 0;
            }
        } else {
            writer.write_all(&h.header_bytes)?;
            writer.write_all(&pes_buf[pes_pos..pes_pos + payload_cap])?;
            pes_pos += payload_cap;
            pes_remain -= payload_cap;
        }
    }

    pes_buf.clear();
    pes_headers.clear();
    *iv_snap_for_pes = None;
    *last_pid = 0xFFFF;
    Ok(())
}

pub(crate) fn decrypt_bbts_streaming(
    input_path: &Path,
    output_path: &Path,
    key: &str,
    progress: &mut ProgressUi,
) -> AppResult<()> {
    let decryption_key = parse_key_spec(key)?;
    let encryptor = AesBlockEncryptor::new(&decryption_key);
    let total_size = std::fs::metadata(input_path)?.len();
    if total_size < TS_PACKET_SIZE as u64 {
        return Err("Input file is too small to be a TS/BBTS file".into());
    }

    let source = File::open(input_path)?;
    let mut reader = BufReader::with_capacity(256 * 1024, source);
    let output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;
    let mut writer = BufWriter::with_capacity(256 * 1024, output);

    let mut ivec = [0u8; 16];
    let mut state_ready = false;
    let mut pmt_pids: HashSet<u16> = HashSet::new();
    let mut target_pids: HashSet<u16> = HashSet::new();
    let mut stream_types: HashMap<u16, u8> = HashMap::new();

    let mut sdt_asm = PSIAssembler::new();
    let mut pmt_asm = PSIAssembler::new();

    let mut pes_buf: Vec<u8> = Vec::new();
    let mut pes_headers: Vec<PESHeaderChunk> = Vec::new();
    let mut iv_snap_for_pes: Option<[u8; 16]> = None;
    let mut last_pid: u16 = 0xFFFF;
    let mut done = 0u64;

    let mut packet = [0u8; TS_PACKET_SIZE];
    loop {
        match reader.read_exact(&mut packet) {
            Ok(()) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                flush_pes_fn(
                    &mut pes_buf,
                    &mut pes_headers,
                    &mut iv_snap_for_pes,
                    &mut last_pid,
                    state_ready,
                    &stream_types,
                    &encryptor,
                    &mut writer,
                )?;
                break;
            }
            Err(e) => return Err(e.into()),
        }

        done += TS_PACKET_SIZE as u64;
        progress.update(done)?;

        if packet[0] != SYNC {
            writer.write_all(&packet)?;
            continue;
        }

        let Some(info) = packet_info(&packet) else {
            writer.write_all(&packet)?;
            continue;
        };

        let pid = info.pid;

        // PAT (PID 0)
        if pid == PID_PAT {
            flush_pes_fn(
                &mut pes_buf,
                &mut pes_headers,
                &mut iv_snap_for_pes,
                &mut last_pid,
                state_ready,
                &stream_types,
                &encryptor,
                &mut writer,
            )?;
            let found = parse_pat(&packet);
            pmt_pids.extend(found.values().copied());
            writer.write_all(&packet)?;
            continue;
        }

        // SDT (PID 17)
        if pid == PID_SDT {
            flush_pes_fn(
                &mut pes_buf,
                &mut pes_headers,
                &mut iv_snap_for_pes,
                &mut last_pid,
                state_ready,
                &stream_types,
                &encryptor,
                &mut writer,
            )?;
            if let Some(sec) = sdt_asm.push(&packet) {
                let mut new_ivec = [0u8; 16];
                if parse_sdt_and_set_iv(&sec, &mut new_ivec) {
                    ivec = new_ivec;
                    state_ready = true;
                }
            }
            if let Some(found_key) = extract_packet_block_key(&packet) {
                ivec[..12].copy_from_slice(&found_key[..12]);
                ivec[12..].fill(0);
                state_ready = true;
            }
            writer.write_all(&packet)?;
            continue;
        }

        // PMT
        if pmt_pids.contains(&pid) {
            flush_pes_fn(
                &mut pes_buf,
                &mut pes_headers,
                &mut iv_snap_for_pes,
                &mut last_pid,
                state_ready,
                &stream_types,
                &encryptor,
                &mut writer,
            )?;
            let found_video_pids = parse_pmt_video_pids(&packet);
            if !found_video_pids.is_empty() {
                target_pids.extend(&found_video_pids);
                for &vpid in &found_video_pids {
                    stream_types.insert(vpid, 0x24);
                }
            }
            if let Some(sec) = pmt_asm.push(&packet) {
                let streams = parse_pmt_streams_map(&sec);
                for (&spid, &stype) in &streams {
                    stream_types.insert(spid, stype);
                    if matches!(stype, 0x01 | 0x02 | 0x1b | 0x24 | 0x06) {
                        target_pids.insert(spid);
                    }
                }
            }
            writer.write_all(&packet)?;
            continue;
        }

        // Dynamic fallback for Video PID if PMT was not yet seen or incomplete
        if target_pids.is_empty()
            && info.payload_unit_start
            && state_ready
            && info.payload_offset.is_some()
            && (32..=256).contains(&pid)
            && pid != PID_SDT
        {
            target_pids.insert(pid);
            stream_types.insert(pid, 0x24);
        }

        if !state_ready || !target_pids.contains(&pid) {
            flush_pes_fn(
                &mut pes_buf,
                &mut pes_headers,
                &mut iv_snap_for_pes,
                &mut last_pid,
                state_ready,
                &stream_types,
                &encryptor,
                &mut writer,
            )?;
            writer.write_all(&packet)?;
            continue;
        }

        let Some(off) = info.payload_offset else {
            flush_pes_fn(
                &mut pes_buf,
                &mut pes_headers,
                &mut iv_snap_for_pes,
                &mut last_pid,
                state_ready,
                &stream_types,
                &encryptor,
                &mut writer,
            )?;
            writer.write_all(&packet)?;
            continue;
        };

        if off >= TS_PACKET_SIZE {
            flush_pes_fn(
                &mut pes_buf,
                &mut pes_headers,
                &mut iv_snap_for_pes,
                &mut last_pid,
                state_ready,
                &stream_types,
                &encryptor,
                &mut writer,
            )?;
            writer.write_all(&packet)?;
            continue;
        }

        let mut is_new_pes = info.payload_unit_start;
        if off + 4 <= TS_PACKET_SIZE
            && packet[off] == 0x00
            && packet[off + 1] == 0x00
            && packet[off + 2] == 0x01
        {
            let sid = packet[off + 3];
            if sid == 0xC0 || (sid & 0xF0) == 0xE0 {
                is_new_pes = true;
            }
        }

        if is_new_pes && !pes_buf.is_empty() {
            flush_pes_fn(
                &mut pes_buf,
                &mut pes_headers,
                &mut iv_snap_for_pes,
                &mut last_pid,
                state_ready,
                &stream_types,
                &encryptor,
                &mut writer,
            )?;
        }

        if !is_new_pes && pes_buf.is_empty() {
            writer.write_all(&packet)?;
            continue;
        }

        if is_new_pes {
            iv_snap_for_pes = Some(ivec);
        }

        last_pid = pid;

        pes_buf.extend_from_slice(&packet[off..]);
        pes_headers.push(PESHeaderChunk {
            header_bytes: packet[..off].to_vec(),
            header_size: off,
        });
    }

    writer.flush()?;
    progress.finish()?;
    Ok(())
}
