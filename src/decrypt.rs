use crate::common::{AppResult, VideoMode, TS_PACKET_SIZE};
use crate::crypto::{parse_key_spec, AesBlockEncryptor};
use crate::hevc::decrypt_es;
use crate::ts::{
    extract_packet_block_key, make_adaptation_only_packet_from_original,
    make_payload_packet_from_original, packet_info, parse_pat, parse_pmt_video_pids,
    update_pes_packet_length_if_needed,
};
use crate::ui::ProgressUi;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

#[derive(Clone)]
struct GroupEntry {
    offset: u64,
    packet: [u8; TS_PACKET_SIZE],
}

struct PacketPart {
    offset: u64,
    packet: [u8; TS_PACKET_SIZE],
    payload_unit_start: bool,
    pes_header: Vec<u8>,
}

fn patch_group_in_output(
    output: &mut File,
    group_entries: &[GroupEntry],
    block_key: Option<&[u8; 16]>,
    encryptor: &AesBlockEncryptor,
    decryption_key: &[u8; 16],
    mode: VideoMode,
) -> AppResult<bool> {
    if group_entries.is_empty() || block_key.is_none() {
        return Ok(false);
    }
    let block_key = block_key.unwrap();
    let mut payload = Vec::new();
    let mut packet_parts = Vec::new();

    for entry in group_entries {
        let Some(info) = packet_info(&entry.packet) else {
            continue;
        };
        let Some(payload_offset) = info.payload_offset else {
            continue;
        };
        let mut pes_header = Vec::new();
        let mut payload_start = payload_offset;
        if info.payload_unit_start {
            let packet_payload = &entry.packet[payload_offset..];
            if packet_payload.len() >= 9 && packet_payload.starts_with(&[0x00, 0x00, 0x01]) {
                let pes_header_size = 9 + packet_payload[8] as usize;
                if pes_header_size <= packet_payload.len() {
                    pes_header.extend_from_slice(&packet_payload[..pes_header_size]);
                    payload_start = payload_offset + pes_header_size;
                }
            }
        }
        packet_parts.push(PacketPart {
            offset: entry.offset,
            packet: entry.packet,
            payload_unit_start: info.payload_unit_start,
            pes_header,
        });
        payload.extend_from_slice(&entry.packet[payload_start..]);
    }

    if packet_parts.is_empty() {
        return Ok(false);
    }

    let decrypted = decrypt_es(&payload, block_key, encryptor, decryption_key, mode);
    let total_capacity: usize = packet_parts
        .iter()
        .map(|part| {
            let payload_offset = packet_info(&part.packet)
                .and_then(|info| info.payload_offset)
                .filter(|&offset| offset <= TS_PACKET_SIZE)
                .unwrap_or(4);
            let prefix_len = if part.payload_unit_start {
                part.pes_header.len()
            } else {
                0
            };
            TS_PACKET_SIZE
                .saturating_sub(payload_offset)
                .saturating_sub(prefix_len)
        })
        .sum();

    if decrypted.len() > total_capacity {
        return Err(format!(
            "Metadata patch needs {} extra byte(s), but this PES has no packet capacity left",
            decrypted.len() - total_capacity
        )
        .into());
    }

    let mut position = 0usize;
    let mut ended = false;
    let return_position = output.stream_position()?;

    for part in packet_parts {
        if ended {
            let rebuilt = make_adaptation_only_packet_from_original(&part.packet);
            output.seek(SeekFrom::Start(part.offset))?;
            output.write_all(&rebuilt)?;
            continue;
        }

        let mut prefix = if part.payload_unit_start {
            part.pes_header
        } else {
            Vec::new()
        };
        if !prefix.is_empty() {
            prefix = update_pes_packet_length_if_needed(&prefix, decrypted.len());
        }

        let payload_offset = packet_info(&part.packet)
            .and_then(|info| info.payload_offset)
            .filter(|&offset| offset <= TS_PACKET_SIZE)
            .unwrap_or(4);
        let capacity = TS_PACKET_SIZE
            .saturating_sub(payload_offset)
            .saturating_sub(prefix.len());
        let remaining = decrypted.len().saturating_sub(position);

        let rebuilt = if remaining == 0 {
            ended = true;
            if !prefix.is_empty() {
                make_payload_packet_from_original(&part.packet, &prefix)
            } else {
                make_adaptation_only_packet_from_original(&part.packet)
            }
        } else {
            let take = capacity.min(remaining);
            let mut packet_payload = prefix;
            packet_payload.extend_from_slice(&decrypted[position..position + take]);
            position += take;
            let rebuilt = make_payload_packet_from_original(&part.packet, &packet_payload);
            if position >= decrypted.len() {
                ended = true;
            }
            rebuilt
        };

        output.seek(SeekFrom::Start(part.offset))?;
        output.write_all(&rebuilt)?;
    }

    output.seek(SeekFrom::Start(return_position))?;
    Ok(true)
}

fn flush_group(
    output: &mut File,
    pid: u16,
    current_groups: &mut HashMap<u16, Vec<GroupEntry>>,
    current_group_keys: &mut HashMap<u16, Option<[u8; 16]>>,
    active_block_key: Option<[u8; 16]>,
    encryptor: &AesBlockEncryptor,
    decryption_key: &[u8; 16],
    mode: VideoMode,
) -> AppResult<()> {
    let group = current_groups.remove(&pid).unwrap_or_default();
    let group_key = current_group_keys.get(&pid).copied().flatten();
    if !group.is_empty() {
        patch_group_in_output(
            output,
            &group,
            group_key.as_ref(),
            encryptor,
            decryption_key,
            mode,
        )?;
    }
    current_groups.insert(pid, Vec::new());
    current_group_keys.insert(pid, active_block_key);
    Ok(())
}

pub(crate) fn decrypt_bbts_streaming(
    input_path: &Path,
    output_path: &Path,
    key: &str,
    progress: &mut ProgressUi,
    mode: VideoMode,
) -> AppResult<()> {
    let decryption_key = parse_key_spec(key)?;
    let encryptor = AesBlockEncryptor::new(&decryption_key);
    let total_size = std::fs::metadata(input_path)?.len();
    if total_size < TS_PACKET_SIZE as u64 {
        return Err("Input file is too small to be a TS/BBTS file".into());
    }

    let mut source = File::open(input_path)?;
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;

    let mut pmt_pids: HashSet<u16> = HashSet::new();
    let mut target_pids: HashSet<u16> = HashSet::new();
    let mut fallback_video_pid: Option<u16> = None;
    let mut active_block_key: Option<[u8; 16]> = None;
    let mut current_groups: HashMap<u16, Vec<GroupEntry>> = HashMap::new();
    let mut current_group_keys: HashMap<u16, Option<[u8; 16]>> = HashMap::new();
    let mut done = 0u64;

    loop {
        let mut packet = [0u8; TS_PACKET_SIZE];
        let mut read_total = 0usize;
        while read_total < TS_PACKET_SIZE {
            let count = source.read(&mut packet[read_total..])?;
            if count == 0 {
                break;
            }
            read_total += count;
        }
        if read_total == 0 {
            break;
        }
        if read_total != TS_PACKET_SIZE {
            return Err("Input ends with an incomplete 188-byte TS packet".into());
        }

        let output_offset = output.stream_position()?;
        output.write_all(&packet)?;
        done += TS_PACKET_SIZE as u64;

        let info = packet_info(&packet);
        if let Some(info_ref) = info.as_ref() {
            if info_ref.pid == 17 {
                if let Some(found_key) = extract_packet_block_key(&packet) {
                    active_block_key = Some(found_key);
                }
            }

            if info_ref.pid == 0 {
                let found_programs = parse_pat(&packet);
                pmt_pids.extend(found_programs.values().copied());
            } else if pmt_pids.contains(&info_ref.pid) {
                let found_video_pids = parse_pmt_video_pids(&packet);
                if !found_video_pids.is_empty() {
                    target_pids = found_video_pids.into_iter().collect();
                } else if let Some(pid) = fallback_video_pid {
                    target_pids.clear();
                    target_pids.insert(pid);
                }
            }

            if target_pids.is_empty()
                && info_ref.payload_unit_start
                && active_block_key.is_some()
                && info_ref.payload_offset.is_some()
                && (32..=256).contains(&info_ref.pid)
            {
                fallback_video_pid = Some(info_ref.pid);
                target_pids.clear();
                target_pids.insert(info_ref.pid);
            }

            if target_pids.contains(&info_ref.pid) && info_ref.payload_offset.is_some() {
                let pid = info_ref.pid;
                if info_ref.payload_unit_start {
                    if current_groups.get(&pid).is_some_and(|group| !group.is_empty()) {
                        flush_group(
                            &mut output,
                            pid,
                            &mut current_groups,
                            &mut current_group_keys,
                            active_block_key,
                            &encryptor,
                            &decryption_key,
                            mode,
                        )?;
                    }
                    current_groups.insert(pid, Vec::new());
                    current_group_keys.insert(pid, active_block_key);
                }
                if let Some(group) = current_groups.get_mut(&pid) {
                    group.push(GroupEntry {
                        offset: output_offset,
                        packet,
                    });
                }
            }
        }

        progress.update(done)?;
    }

    let pids: Vec<u16> = current_groups.keys().copied().collect();
    for pid in pids {
        if current_groups.get(&pid).is_some_and(|group| !group.is_empty()) {
            flush_group(
                &mut output,
                pid,
                &mut current_groups,
                &mut current_group_keys,
                active_block_key,
                &encryptor,
                &decryption_key,
                mode,
            )?;
        }
    }
    output.flush()?;
    progress.finish()?;

    Ok(())
}
