use crate::common::TS_PACKET_SIZE;
use crate::crypto::decode_hex_16;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub(crate) struct PacketInfo {
    pub(crate) pid: u16,
    pub(crate) payload_unit_start: bool,
    pub(crate) adaptation_field_control: u8,
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
                adaptation_field_control,
                payload_offset: None,
            });
        }
        let adaptation_length = packet[payload_offset] as usize;
        payload_offset += 1 + adaptation_length;
        if payload_offset > TS_PACKET_SIZE {
            return Some(PacketInfo {
                pid,
                payload_unit_start,
                adaptation_field_control,
                payload_offset: None,
            });
        }
    }

    if adaptation_field_control != 1 && adaptation_field_control != 3 {
        return Some(PacketInfo {
            pid,
            payload_unit_start,
            adaptation_field_control,
            payload_offset: None,
        });
    }

    Some(PacketInfo {
        pid,
        payload_unit_start,
        adaptation_field_control,
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

fn pad_or_truncate_packet(mut data: Vec<u8>) -> [u8; TS_PACKET_SIZE] {
    if data.len() < TS_PACKET_SIZE {
        data.resize(TS_PACKET_SIZE, 0xff);
    } else if data.len() > TS_PACKET_SIZE {
        data.truncate(TS_PACKET_SIZE);
    }
    let mut output = [0u8; TS_PACKET_SIZE];
    output.copy_from_slice(&data);
    output
}

pub(crate) fn make_payload_packet_from_original(
    packet: &[u8; TS_PACKET_SIZE],
    payload: &[u8],
) -> [u8; TS_PACKET_SIZE] {
    let info = packet_info(packet);
    let mut payload_offset = info
        .as_ref()
        .and_then(|value| value.payload_offset)
        .unwrap_or(4);
    let mut adaptation_field_control = info
        .as_ref()
        .map(|value| value.adaptation_field_control)
        .unwrap_or(1);

    if payload_offset > TS_PACKET_SIZE {
        payload_offset = 4;
        adaptation_field_control = 1;
    }

    let original_header = &packet[..payload_offset];
    let payload_capacity = TS_PACKET_SIZE.saturating_sub(original_header.len());
    let payload = &payload[..payload.len().min(payload_capacity)];
    let stuffing_needed = payload_capacity.saturating_sub(payload.len());

    if stuffing_needed == 0 {
        let mut output_header = original_header.to_vec();
        if output_header.len() >= 4 {
            output_header[3] =
                (output_header[3] & 0xcf) | ((adaptation_field_control & 0x03) << 4);
        }
        output_header.extend_from_slice(payload);
        return pad_or_truncate_packet(output_header);
    }

    if adaptation_field_control == 3 && original_header.len() >= 5 {
        let old_length = original_header[4] as usize;
        let new_length = old_length + stuffing_needed;
        if new_length <= 183 {
            let mut output_header = original_header.to_vec();
            output_header[3] = (output_header[3] & 0xcf) | 0x30;
            output_header[4] = new_length as u8;
            output_header.extend(std::iter::repeat(0xff).take(stuffing_needed));
            output_header.extend_from_slice(payload);
            return pad_or_truncate_packet(output_header);
        }
    }

    let mut base_header = packet[..4].to_vec();
    base_header[3] = (base_header[3] & 0xcf) | 0x30;
    let adaptation_length = stuffing_needed - 1;
    let mut output = base_header;
    output.push(adaptation_length as u8);
    if adaptation_length > 0 {
        output.push(0x00);
        if adaptation_length > 1 {
            output.extend(std::iter::repeat(0xff).take(adaptation_length - 1));
        }
    }
    output.extend_from_slice(payload);
    pad_or_truncate_packet(output)
}

pub(crate) fn make_adaptation_only_packet_from_original(
    packet: &[u8; TS_PACKET_SIZE],
) -> [u8; TS_PACKET_SIZE] {
    let mut output = Vec::with_capacity(TS_PACKET_SIZE);
    let mut header = packet[..4].to_vec();
    header[3] = (header[3] & 0xcf) | 0x20;
    output.extend_from_slice(&header);
    output.push(183);

    let info = packet_info(packet);
    let mut content = Vec::new();
    if let Some(info) = info {
        if info.adaptation_field_control == 3 && packet.len() >= 5 {
            let old_length = packet[4] as usize;
            let old_end = (5 + old_length).min(TS_PACKET_SIZE);
            content.extend_from_slice(&packet[5..old_end]);
        }
    }
    content.truncate(183);
    output.extend_from_slice(&content);
    output.extend(std::iter::repeat(0xff).take(183 - content.len()));
    pad_or_truncate_packet(output)
}

pub(crate) fn update_pes_packet_length_if_needed(prefix: &[u8], payload_length: usize) -> Vec<u8> {
    if prefix.len() < 6 || !prefix.starts_with(&[0x00, 0x00, 0x01]) {
        return prefix.to_vec();
    }
    let current_length = ((prefix[4] as u16) << 8) | prefix[5] as u16;
    if current_length == 0 {
        return prefix.to_vec();
    }
    let new_length = prefix.len().saturating_add(payload_length).saturating_sub(6);
    if new_length > 0xffff {
        return prefix.to_vec();
    }
    let mut output = prefix.to_vec();
    output[4] = ((new_length >> 8) & 0xff) as u8;
    output[5] = (new_length & 0xff) as u8;
    output
}
