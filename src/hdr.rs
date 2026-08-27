use crate::crypto::{decrypt_nal_vb, AesBlockEncryptor};

const NAL_PREFIX_SEI: u8 = 39;
const NAL_SUFFIX_SEI: u8 = 40;

const SEI_USER_DATA_REGISTERED_ITU_T_T35: u32 = 4;
const SEI_MASTERING_DISPLAY_COLOUR_VOLUME: u32 = 137;
const SEI_CONTENT_LIGHT_LEVEL_INFO: u32 = 144;
const SEI_ALTERNATIVE_TRANSFER_CHARACTERISTICS: u32 = 147;

const HDR_VIVID_COUNTRY_CODE: u8 = 0x26;
const HDR_VIVID_PROVIDER_CODE: u16 = 0x0004;
const HDR_VIVID_PROVIDER_ORIENTED_CODE: u16 = 0x0005;
const HDR_VIVID_SYSTEM_START_CODE_V1: u8 = 0x01;

const D65_WHITE_POINT: (u16, u16) = (15_635, 16_450);

const DISPLAY_P3_PRIMARIES: [(u16, u16); 3] = [
    (13_250, 34_500),
    (7_500, 3_000),
    (34_000, 16_000),
];
const BT2020_PRIMARIES: [(u16, u16); 3] = [
    (8_500, 39_850),
    (6_550, 2_300),
    (35_400, 14_600),
];

const MASTERING_PRESET_TOLERANCE: u16 = 100;
const WHITE_POINT_TOLERANCE: u16 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MasteringGamut {
    DisplayP3,
    Bt2020,
    Custom,
}

#[derive(Clone, Copy, Debug)]
struct MasteringDisplayMetadata {
    primaries: [(u16, u16); 3],
    white_point: (u16, u16),
    max_luminance: u32,
    min_luminance: u32,
}

#[derive(Clone, Debug)]
struct SeiMessage {
    payload_type: u32,
    payload: Vec<u8>,
}

fn start_code_length(unit: &[u8]) -> Option<usize> {
    if unit.starts_with(&[0x00, 0x00, 0x00, 0x01]) {
        Some(4)
    } else if unit.starts_with(&[0x00, 0x00, 0x01]) {
        Some(3)
    } else {
        None
    }
}

fn hevc_nal_type(unit: &[u8]) -> Option<u8> {
    let offset = start_code_length(unit)?;
    Some((unit.get(offset)? >> 1) & 0x3f)
}

fn ebsp_to_rbsp(ebsp: &[u8]) -> Vec<u8> {
    let mut rbsp = Vec::with_capacity(ebsp.len());
    let mut zeros = 0usize;

    for &value in ebsp {
        if zeros == 2 && value == 0x03 {
            zeros = 0;
            continue;
        }

        rbsp.push(value);
        if value == 0x00 {
            zeros = (zeros + 1).min(2);
        } else {
            zeros = 0;
        }
    }

    rbsp
}

fn rbsp_to_ebsp(rbsp: &[u8]) -> Vec<u8> {
    let mut ebsp = Vec::with_capacity(rbsp.len() + rbsp.len() / 32 + 8);
    let mut zeros = 0usize;

    for &value in rbsp {
        if zeros >= 2 && matches!(value, 0x00 | 0x01 | 0x02 | 0x03) {
            ebsp.push(0x03);
            zeros = 0;
        }

        ebsp.push(value);
        if value == 0x00 {
            zeros = (zeros + 1).min(2);
        } else {
            zeros = 0;
        }
    }

    ebsp
}

fn read_ff_value(data: &[u8], position: &mut usize) -> Option<u32> {
    let mut value = 0u32;
    loop {
        let byte = *data.get(*position)?;
        *position += 1;
        value = value.checked_add(byte as u32)?;
        if byte != 0xff {
            return Some(value);
        }
    }
}

fn write_ff_value(mut value: usize, output: &mut Vec<u8>) {
    while value >= 0xff {
        output.push(0xff);
        value -= 0xff;
    }
    output.push(value as u8);
}

fn parse_complete_sei_unit(unit: &[u8]) -> Option<([u8; 2], Vec<SeiMessage>)> {
    let start = start_code_length(unit)?;
    let nal_type = hevc_nal_type(unit)?;
    if nal_type != NAL_PREFIX_SEI && nal_type != NAL_SUFFIX_SEI {
        return None;
    }

    let header = [*unit.get(start)?, *unit.get(start + 1)?];
    let payload = unit.get(start + 2..)?;
    let rbsp = ebsp_to_rbsp(payload);
    let mut position = 0usize;
    let mut messages = Vec::new();

    while position < rbsp.len() {

        if rbsp[position] == 0x80 {
            if rbsp[position + 1..].iter().all(|&value| value == 0x00) {
                return Some((header, messages));
            }
            return None;
        }

        let payload_type = read_ff_value(&rbsp, &mut position)?;
        let payload_size = read_ff_value(&rbsp, &mut position)? as usize;
        let payload_end = position.checked_add(payload_size)?;
        if payload_end > rbsp.len() {
            return None;
        }

        messages.push(SeiMessage {
            payload_type,
            payload: rbsp[position..payload_end].to_vec(),
        });
        position = payload_end;
    }

    None
}

fn build_canonical_sei_unit(header: [u8; 2], messages: &[SeiMessage]) -> Vec<u8> {
    let mut rbsp = Vec::new();
    for message in messages {
        write_ff_value(message.payload_type as usize, &mut rbsp);
        write_ff_value(message.payload.len(), &mut rbsp);
        rbsp.extend_from_slice(&message.payload);
    }
    rbsp.push(0x80);

    let ebsp = rbsp_to_ebsp(&rbsp);
    let mut output = Vec::with_capacity(4 + 2 + ebsp.len());
    output.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    output.extend_from_slice(&header);
    output.extend_from_slice(&ebsp);
    output
}

fn read_be_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn is_hdr_vivid_v1_t35(payload: &[u8]) -> bool {

    if payload.len() < 13 {
        return false;
    }

    payload[0] == HDR_VIVID_COUNTRY_CODE
        && read_be_u16(payload, 1) == Some(HDR_VIVID_PROVIDER_CODE)
        && read_be_u16(payload, 3) == Some(HDR_VIVID_PROVIDER_ORIENTED_CODE)
        && payload[5] == HDR_VIVID_SYSTEM_START_CODE_V1
}

fn parse_mastering_display(payload: &[u8]) -> Option<MasteringDisplayMetadata> {
    if payload.len() != 24 {
        return None;
    }

    let metadata = MasteringDisplayMetadata {
        primaries: [
            (read_be_u16(payload, 0)?, read_be_u16(payload, 2)?),
            (read_be_u16(payload, 4)?, read_be_u16(payload, 6)?),
            (read_be_u16(payload, 8)?, read_be_u16(payload, 10)?),
        ],
        white_point: (read_be_u16(payload, 12)?, read_be_u16(payload, 14)?),
        max_luminance: read_be_u32(payload, 16)?,
        min_luminance: read_be_u32(payload, 20)?,
    };

    if metadata
        .primaries
        .iter()
        .flat_map(|&(x, y)| [x, y])
        .chain([metadata.white_point.0, metadata.white_point.1])
        .any(|value| value > 50_000)
    {
        return None;
    }
    if metadata.max_luminance < metadata.min_luminance {
        return None;
    }
    Some(metadata)
}

fn coordinate_near(value: u16, target: u16, tolerance: u16) -> bool {
    value.abs_diff(target) <= tolerance
}

fn primaries_near(
    value: &[(u16, u16); 3],
    target: &[(u16, u16); 3],
) -> bool {
    value.iter().zip(target).all(|(&(x, y), &(tx, ty))| {
        coordinate_near(x, tx, MASTERING_PRESET_TOLERANCE)
            && coordinate_near(y, ty, MASTERING_PRESET_TOLERANCE)
    })
}

fn classify_mastering_gamut(metadata: &MasteringDisplayMetadata) -> MasteringGamut {
    if primaries_near(&metadata.primaries, &DISPLAY_P3_PRIMARIES) {
        MasteringGamut::DisplayP3
    } else if primaries_near(&metadata.primaries, &BT2020_PRIMARIES) {
        MasteringGamut::Bt2020
    } else {
        MasteringGamut::Custom
    }
}

fn write_be_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn normalize_mastering_display(payload: &[u8]) -> Option<Vec<u8>> {
    let metadata = parse_mastering_display(payload)?;
    let gamut = classify_mastering_gamut(&metadata);

    let d65 = coordinate_near(metadata.white_point.0, D65_WHITE_POINT.0, WHITE_POINT_TOLERANCE)
        && coordinate_near(metadata.white_point.1, D65_WHITE_POINT.1, WHITE_POINT_TOLERANCE);
    if !d65 || gamut == MasteringGamut::Custom {
        return Some(payload.to_vec());
    }

    let canonical_primaries = match gamut {
        MasteringGamut::DisplayP3 => DISPLAY_P3_PRIMARIES,
        MasteringGamut::Bt2020 => BT2020_PRIMARIES,
        MasteringGamut::Custom => unreachable!(),
    };

    let mut normalized = payload.to_vec();
    for (index, &(x, y)) in canonical_primaries.iter().enumerate() {
        write_be_u16(&mut normalized, index * 4, x);
        write_be_u16(&mut normalized, index * 4 + 2, y);
    }
    write_be_u16(&mut normalized, 12, D65_WHITE_POINT.0);
    write_be_u16(&mut normalized, 14, D65_WHITE_POINT.1);
    Some(normalized)
}

fn is_valid_mastering_display(payload: &[u8]) -> bool {
    parse_mastering_display(payload).is_some()
}

fn parse_content_light_level(payload: &[u8]) -> Option<(u16, u16)> {
    if payload.len() != 4 {
        return None;
    }
    Some((read_be_u16(payload, 0)?, read_be_u16(payload, 2)?))
}

fn is_recognized_hdr_message(message: &SeiMessage) -> bool {
    match message.payload_type {
        SEI_USER_DATA_REGISTERED_ITU_T_T35 => is_hdr_vivid_v1_t35(&message.payload),
        SEI_MASTERING_DISPLAY_COLOUR_VOLUME => is_valid_mastering_display(&message.payload),
        SEI_CONTENT_LIGHT_LEVEL_INFO => parse_content_light_level(&message.payload).is_some(),
        SEI_ALTERNATIVE_TRANSFER_CHARACTERISTICS => message.payload.len() == 1,
        _ => false,
    }
}

fn normalize_hdr_messages(messages: &[SeiMessage]) -> Option<Vec<SeiMessage>> {
    let mut normalized = Vec::with_capacity(messages.len());
    for message in messages {
        let payload = match message.payload_type {
            SEI_MASTERING_DISPLAY_COLOUR_VOLUME => normalize_mastering_display(&message.payload)?,

            SEI_CONTENT_LIGHT_LEVEL_INFO => {
                parse_content_light_level(&message.payload)?;
                message.payload.clone()
            }

            _ => message.payload.clone(),
        };
        normalized.push(SeiMessage {
            payload_type: message.payload_type,
            payload,
        });
    }
    Some(normalized)
}

fn normalized_candidates(candidate: &[u8], original_start_code_length: usize) -> Vec<Vec<u8>> {
    let mut variants = Vec::new();

    if original_start_code_length == 3 && candidate.len() >= 4 {
        let mut normalized = Vec::with_capacity(candidate.len().saturating_sub(3));
        normalized.push(0x00);
        normalized.extend_from_slice(&candidate[..candidate.len() - 4]);
        variants.push(normalized);
    } else {
        variants.push(candidate.to_vec());
    }

    for drop in [0usize, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16] {
        if candidate.len() <= drop + original_start_code_length + 2 {
            continue;
        }

        let end = candidate.len() - drop;
        if original_start_code_length == 3 {
            let mut normalized = Vec::with_capacity(end + 1);
            normalized.push(0x00);
            normalized.extend_from_slice(&candidate[..end]);
            variants.push(normalized);
        } else {
            variants.push(candidate[..end].to_vec());
        }
    }

    variants
}

pub(crate) fn decrypt_hdr_sei_unit(
    unit: &[u8],
    block_key: &[u8; 16],
    encryptor: &AesBlockEncryptor,
    default_trailer_size: usize,
) -> Option<Vec<u8>> {
    let original_start_code_length = start_code_length(unit)?;
    let nal_type = hevc_nal_type(unit)?;
    if nal_type != NAL_PREFIX_SEI && nal_type != NAL_SUFFIX_SEI {
        return None;
    }

    let trailer_candidates = [
        default_trailer_size,
        2usize,
        4usize,
        0usize,
        1usize,
        3usize,
        5usize,
        6usize,
        7usize,
        8usize,
        12usize,
        16usize,
    ];
    let mut tried = [false; 17];

    for trailer_size in trailer_candidates {
        if trailer_size < tried.len() {
            if tried[trailer_size] {
                continue;
            }
            tried[trailer_size] = true;
        }

        let decrypted = decrypt_nal_vb(unit, block_key, encryptor, trailer_size);
        for normalized in normalized_candidates(&decrypted, original_start_code_length) {
            let Some((header, messages)) = parse_complete_sei_unit(&normalized) else {
                continue;
            };
            if messages.iter().any(is_recognized_hdr_message) {
                let messages = normalize_hdr_messages(&messages)?;
                return Some(build_canonical_sei_unit(header, &messages));
            }
        }
    }

    None
}
