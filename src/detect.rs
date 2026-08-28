use crate::common::{AppResult, VideoMode, TS_PACKET_SIZE};
use crate::crypto::{parse_key_spec, AesBlockEncryptor};
use crate::hevc::probe_es;
use crate::ts::{extract_packet_block_key, packet_info, parse_pat, parse_pmt_video_pids};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const MAX_PROBE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROBE_GROUPS: usize = 192;

#[derive(Clone)]
struct ProbeEntry {
    packet: [u8; TS_PACKET_SIZE],
}

#[derive(Default)]
struct DetectionState {
    saw_hdr: bool,
    saw_dolby_vision: bool,
    groups_checked: usize,
}

fn es_payload_from_group(group: &[ProbeEntry]) -> Vec<u8> {
    let mut payload = Vec::new();

    for entry in group {
        let Some(info) = packet_info(&entry.packet) else {
            continue;
        };
        let Some(payload_offset) = info.payload_offset else {
            continue;
        };

        let mut payload_start = payload_offset;
        if info.payload_unit_start {
            let packet_payload = &entry.packet[payload_offset..];
            if packet_payload.len() >= 9 && packet_payload.starts_with(&[0x00, 0x00, 0x01]) {
                let pes_header_size = 9 + packet_payload[8] as usize;
                if pes_header_size <= packet_payload.len() {
                    payload_start = payload_offset + pes_header_size;
                }
            }
        }

        payload.extend_from_slice(&entry.packet[payload_start..]);
    }

    payload
}

fn analyze_group(
    group: &[ProbeEntry],
    block_key: Option<&[u8; 16]>,
    encryptor: &AesBlockEncryptor,
    decryption_key: &[u8; 16],
    state: &mut DetectionState,
) {
    if group.is_empty() || block_key.is_none() {
        return;
    }
    let payload = es_payload_from_group(group);
    if payload.is_empty() {
        return;
    }

    let probe = probe_es(
        &payload,
        block_key.expect("checked above"),
        encryptor,
        decryption_key,
    );

    state.saw_hdr |= probe.hdr;
    state.saw_dolby_vision |= probe.dolby_vision;
    state.groups_checked += 1;
}

fn finalize_detection(state: &DetectionState) -> VideoMode {
    if state.saw_dolby_vision {
        VideoMode::DolbyVision
    } else if state.saw_hdr {
        VideoMode::Hdr
    } else {
        VideoMode::Sdr
    }
}

pub(crate) fn detect_stream_mode(input_path: &Path, key: &str) -> AppResult<VideoMode> {
    let decryption_key = parse_key_spec(key)?;
    let encryptor = AesBlockEncryptor::new(&decryption_key);
    let mut source = File::open(input_path)?;

    let mut pmt_pids: HashSet<u16> = HashSet::new();
    let mut target_pids: HashSet<u16> = HashSet::new();
    let mut fallback_video_pid: Option<u16> = None;
    let mut active_block_key: Option<[u8; 16]> = None;
    let mut current_groups: HashMap<u16, Vec<ProbeEntry>> = HashMap::new();
    let mut current_group_keys: HashMap<u16, Option<[u8; 16]>> = HashMap::new();
    let mut state = DetectionState::default();
    let mut bytes_read = 0u64;

    while bytes_read < MAX_PROBE_BYTES && state.groups_checked < MAX_PROBE_GROUPS {
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
        bytes_read += TS_PACKET_SIZE as u64;

        let Some(info) = packet_info(&packet) else {
            continue;
        };

        if info.pid == 17 {
            if let Some(found_key) = extract_packet_block_key(&packet) {
                active_block_key = Some(found_key);
            }
        }

        if info.pid == 0 {
            let found_programs = parse_pat(&packet);
            pmt_pids.extend(found_programs.values().copied());
        } else if pmt_pids.contains(&info.pid) {
            let found_video_pids = parse_pmt_video_pids(&packet);
            if !found_video_pids.is_empty() {
                target_pids = found_video_pids.into_iter().collect();
            } else if let Some(pid) = fallback_video_pid {
                target_pids.clear();
                target_pids.insert(pid);
            }
        }

        if target_pids.is_empty()
            && info.payload_unit_start
            && active_block_key.is_some()
            && info.payload_offset.is_some()
            && (32..=256).contains(&info.pid)
        {
            fallback_video_pid = Some(info.pid);
            target_pids.clear();
            target_pids.insert(info.pid);
        }

        if target_pids.contains(&info.pid) && info.payload_offset.is_some() {
            let pid = info.pid;
            if info.payload_unit_start {
                if let Some(group) = current_groups.get(&pid) {
                    if !group.is_empty() {
                        let group_key = current_group_keys.get(&pid).copied().flatten();
                        analyze_group(
                            group,
                            group_key.as_ref(),
                            &encryptor,
                            &decryption_key,
                            &mut state,
                        );
                        if state.saw_dolby_vision {
                            return Ok(VideoMode::DolbyVision);
                        }
                    }
                }
                current_groups.insert(pid, Vec::new());
                current_group_keys.insert(pid, active_block_key);
            }

            if let Some(group) = current_groups.get_mut(&pid) {
                group.push(ProbeEntry { packet });
            }
        }
    }

    let pids: Vec<u16> = current_groups.keys().copied().collect();
    for pid in pids {
        if state.groups_checked >= MAX_PROBE_GROUPS {
            break;
        }
        let group = current_groups.get(&pid).cloned().unwrap_or_default();
        if !group.is_empty() {
            let group_key = current_group_keys.get(&pid).copied().flatten();
            analyze_group(
                &group,
                group_key.as_ref(),
                &encryptor,
                &decryption_key,
                &mut state,
            );
        }
    }

    Ok(finalize_detection(&state))
}
