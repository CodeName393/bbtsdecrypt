use crate::common::TS_PACKET_SIZE;
use crate::crypto::decode_hex_16;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub(crate) struct PacketInfo {
    pub(crate) pid: u16,
    pub(crate) payload_unit_start: bool,
    pub(crate) payload_offset: Option<usize>,
}

pub(crate) fn packet_info(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() != TS_PACKET_SIZE || packet[0] != 0x47 {
        return None;
    }

    let pid = (((packet[1] & 0x1f) as u16) << 8) | packet[2] as u16;
    let payload_unit_start = (packet[1] & 0x40) != 0;
    let adaptation_field_control = (packet[3] >> 4) & 0x03;
    let mut payload_offset = 4usize;

    if adaptation_field_control == 2 || adaptation_field_control == 3 {
        if payload_offset >= TS_PACKET_SIZE {
            return Some(PacketInfo {
                pid,
                payload_unit_start,
                payload_offset: None,
            });
        }
        let adaptation_length = packet[payload_offset] as usize;
        payload_offset += 1 + adaptation_length;
        if payload_offset > TS_PACKET_SIZE {
            return Some(PacketInfo {
                pid,
                payload_unit_start,
                payload_offset: None,
            });
        }
    }

    if adaptation_field_control != 1 && adaptation_field_control != 3 {
        return Some(PacketInfo {
            pid,
            payload_unit_start,
            payload_offset: None,
        });
    }

    Some(PacketInfo {
        pid,
        payload_unit_start,
        payload_offset: Some(payload_offset),
    })
}

pub(crate) fn parse_pat(packet: &[u8]) -> HashMap<u16, u16> {
    let mut programs = HashMap::new();
    let Some(info) = packet_info(packet) else {
        return programs;
    };
    if info.pid != 0 {
        return programs;
    }
    let Some(payload_offset) = info.payload_offset else {
        return programs;
    };

    let mut payload = &packet[payload_offset..];
    if info.payload_unit_start {
        if payload.is_empty() {
            return programs;
        }
        let pointer = payload[0] as usize;
        if 1 + pointer > payload.len() {
            return programs;
        }
        payload = &payload[1 + pointer..];
    }

    if payload.len() < 8 || payload[0] != 0x00 {
        return programs;
    }
    let section_length = (((payload[1] & 0x0f) as usize) << 8) | payload[2] as usize;
    let section_end = 3usize.saturating_add(section_length);
    if section_end > payload.len() {
        return programs;
    }
    let section = &payload[..section_end];
    if section.len() < 12 {
        return programs;
    }

    let mut i = 8usize;
    let end = section.len().saturating_sub(4);
    while i + 4 <= end {
        let program_number = ((section[i] as u16) << 8) | section[i + 1] as u16;
        let program_map_pid = (((section[i + 2] & 0x1f) as u16) << 8) | section[i + 3] as u16;
        if program_number != 0 {
            programs.insert(program_number, program_map_pid);
        }
        i += 4;
    }
    programs
}

fn has_dovi_registration(descriptors: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 2 <= descriptors.len() {
        let tag = descriptors[i];
        let size = descriptors[i + 1] as usize;
        if i + 2 + size > descriptors.len() {
            break;
        }
        let value = &descriptors[i + 2..i + 2 + size];
        if tag == 0x05 && value == b"DOVI" {
            return true;
        }
        i += 2 + size;
    }
    false
}

fn stream_type_is_video(stream_type: u8) -> bool {
    matches!(stream_type, 0x01 | 0x02 | 0x1b | 0x24)
}

pub(crate) fn parse_pmt_video_pids(packet: &[u8]) -> Vec<u16> {
    let mut video_pids = Vec::new();
    let Some(info) = packet_info(packet) else {
        return video_pids;
    };
    let Some(payload_offset) = info.payload_offset else {
        return video_pids;
    };

    let mut payload = &packet[payload_offset..];
    if info.payload_unit_start {
        if payload.is_empty() {
            return video_pids;
        }
        let pointer = payload[0] as usize;
        if 1 + pointer > payload.len() {
            return video_pids;
        }
        payload = &payload[1 + pointer..];
    }

    if payload.len() < 12 || payload[0] != 0x02 {
        return video_pids;
    }
    let section_length = (((payload[1] & 0x0f) as usize) << 8) | payload[2] as usize;
    let section_end = 3usize.saturating_add(section_length);
    if section_end > payload.len() {
        return video_pids;
    }
    let section = &payload[..section_end];
    if section.len() < 16 {
        return video_pids;
    }

    let program_info_length = (((section[10] & 0x0f) as usize) << 8) | section[11] as usize;
    let mut i = 12usize.saturating_add(program_info_length);
    let end = section.len().saturating_sub(4);

    while i + 5 <= end {
        let stream_type = section[i];
        let elementary_pid = (((section[i + 1] & 0x1f) as u16) << 8) | section[i + 2] as u16;
        let es_info_length = (((section[i + 3] & 0x0f) as usize) << 8) | section[i + 4] as usize;
        if i + 5 + es_info_length > section.len() {
            break;
        }

        let descriptors = &section[i + 5..i + 5 + es_info_length];
        if stream_type_is_video(stream_type)
            || (stream_type == 0x06 && has_dovi_registration(descriptors))
        {
            video_pids.push(elementary_pid);
        }
        i += 5 + es_info_length;
    }

    video_pids
}

fn printable_bytes(data: &[u8]) -> Vec<u8> {
    data.iter()
        .copied()
        .filter(|value| (32..=126).contains(value))
        .collect()
}

fn extract_hex_marker_key(data: &[u8]) -> Option<[u8; 16]> {
    let text = printable_bytes(data);
    if text.len() < 35 {
        return None;
    }
    for i in 0..=text.len() - 35 {
        if text[i] == b'|' && text[i + 1] == b'v' && text[i + 34] == b'|' {
            if let Some(key) = decode_hex_16(&text[i + 2..i + 34]) {
                return Some(key);
            }
        }
    }
    None
}

pub(crate) fn extract_packet_block_key(packet: &[u8]) -> Option<[u8; 16]> {
    if packet.len() <= 4 {
        None
    } else {
        extract_hex_marker_key(&packet[4..])
    }
}

pub(crate) struct PSIAssembler {
    buf: Vec<u8>,
    expected_total: Option<usize>,
    collecting: bool,
}

impl PSIAssembler {
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::new(),
            expected_total: None,
            collecting: false,
        }
    }

    pub(crate) fn push(&mut self, pkt: &[u8]) -> Option<Vec<u8>> {
        if pkt.len() != TS_PACKET_SIZE {
            return None;
        }
        let info = packet_info(pkt)?;
        let off = info.payload_offset?;
        if off >= TS_PACKET_SIZE {
            return None;
        }

        let mut payload = &pkt[off..];

        if info.payload_unit_start {
            if payload.is_empty() {
                return None;
            }
            let pointer = payload[0] as usize;
            if 1 + pointer > payload.len() {
                return None;
            }
            payload = &payload[1 + pointer..];
            self.buf.clear();
            self.expected_total = None;
            self.collecting = true;
        }

        if !self.collecting {
            return None;
        }

        self.buf.extend_from_slice(payload);

        if self.expected_total.is_none() && self.buf.len() >= 3 {
            let section_length = (((self.buf[1] & 0x0f) as usize) << 8) | self.buf[2] as usize;
            self.expected_total = Some(3 + section_length);
        }

        if let Some(expected) = self.expected_total {
            if self.buf.len() >= expected {
                let section = self.buf[..expected].to_vec();
                self.buf.clear();
                self.expected_total = None;
                self.collecting = false;
                return Some(section);
            }
        }

        None
    }
}

pub(crate) fn parse_sdt_and_set_iv(section: &[u8], ivec: &mut [u8; 16]) -> bool {
    if section.len() < 16 || section[0] != 0x42 {
        return false;
    }
    let section_length = (((section[1] & 0x0f) as usize) << 8) | section[2] as usize;
    let end = 3 + section_length;
    if end > section.len() {
        return false;
    }

    let mut pos = 3 + 8;
    while pos + 5 <= end.saturating_sub(4) {
        let desc_loop_len = (((section[pos + 3] & 0x0f) as usize) << 8) | section[pos + 4] as usize;
        let mut dpos = pos + 5;
        let dend = dpos + desc_loop_len;

        while dpos + 2 <= dend && dpos + 2 <= end.saturating_sub(4) {
            let tag = section[dpos];
            let length = section[dpos + 1] as usize;
            dpos += 2;
            if dpos + length > section.len() {
                break;
            }
            let body = &section[dpos..dpos + length];
            dpos += length;

            if tag == 0x48 && body.len() >= 3 {
                let provider_len = body[1] as usize;
                if 2 + provider_len >= body.len() {
                    continue;
                }
                let sn_len_idx = 2 + provider_len;
                let sn_len = body[sn_len_idx] as usize;
                if sn_len_idx + 1 + sn_len > body.len() {
                    continue;
                }
                let service_name = String::from_utf8_lossy(&body[sn_len_idx + 1..sn_len_idx + 1 + sn_len]);

                if !service_name.contains("mdcm|") {
                    continue;
                }

                let parts: Vec<&str> = service_name.split('|').collect();
                if parts.len() < 4 {
                    continue;
                }

                let mut iv_hex = parts[3].trim();
                if iv_hex.is_empty() {
                    continue;
                }
                if iv_hex.starts_with('v') || iv_hex.starts_with('V') {
                    iv_hex = &iv_hex[1..];
                }

                if let Some(iv_bin) = decode_hex_16(iv_hex.as_bytes()) {
                    *ivec = [0u8; 16];
                    ivec[..12].copy_from_slice(&iv_bin[..12]);
                    return true;
                }
            }
        }
        pos = dend;
    }
    false
}

pub(crate) fn parse_pmt_streams_map(section: &[u8]) -> HashMap<u16, u8> {
    let mut streams = HashMap::new();
    if section.len() < 12 || section[0] != 0x02 {
        return streams;
    }
    let section_length = (((section[1] & 0x0f) as usize) << 8) | section[2] as usize;
    let end = 3 + section_length;
    if end > section.len() {
        return streams;
    }

    let program_info_length = (((section[10] & 0x0f) as usize) << 8) | section[11] as usize;
    let mut pos = 12 + program_info_length;

    while pos + 5 <= end.saturating_sub(4) {
        let stream_type = section[pos];
        let elementary_pid = (((section[pos + 1] & 0x1f) as u16) << 8) | section[pos + 2] as u16;
        let es_info_length = (((section[pos + 3] & 0x0f) as usize) << 8) | section[pos + 4] as usize;
        streams.insert(elementary_pid, stream_type);
        pos += 5 + es_info_length;
    }
    streams
}
