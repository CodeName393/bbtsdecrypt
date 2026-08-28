use crate::crypto::decrypt_es_sparse_stripped_with_padding;

pub(crate) fn mpeg_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &value in data {
        crc ^= (value as u32) << 24;
        for _ in 0..8 {
            crc = if (crc & 0x8000_0000) != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn hevc_nal_type_from_annexb_unit(unit: &[u8]) -> i32 {
    let offset = if unit.starts_with(&[0x00, 0x00, 0x00, 0x01]) {
        4
    } else if unit.starts_with(&[0x00, 0x00, 0x01]) {
        3
    } else {
        return -1;
    };
    if unit.len() < offset + 2 {
        return -1;
    }
    ((unit[offset] >> 1) & 0x3f) as i32
}

fn dolby_rpu_rbsp_positions_from_ebsp(ebsp: &[u8]) -> Vec<usize> {
    let mut positions = Vec::with_capacity(ebsp.len());
    let mut zeros = 0usize;
    for (index, &value) in ebsp.iter().enumerate() {
        if zeros == 2 && value == 0x03 {
            zeros = 0;
            continue;
        }
        positions.push(index);
        if value == 0x00 {
            zeros += 1;
            if zeros > 2 {
                zeros = 2;
            }
        } else {
            zeros = 0;
        }
    }
    positions
}

fn find_valid_dolby_rpu_rbsp_end(rbsp: &[u8]) -> usize {
    if rbsp.len() < 8 || rbsp[0] != 0x19 {
        return rbsp.len();
    }
    for end_index in (6..rbsp.len()).rev() {
        if rbsp[end_index] != 0x80 {
            continue;
        }
        let crc_start = end_index - 4;
        if crc_start <= 1 {
            continue;
        }
        let received_crc = u32::from_be_bytes([
            rbsp[crc_start],
            rbsp[crc_start + 1],
            rbsp[crc_start + 2],
            rbsp[crc_start + 3],
        ]);
        let expected_crc = mpeg_crc32(&rbsp[1..crc_start]);
        if received_crc == expected_crc {
            return end_index + 1;
        }
    }
    rbsp.len()
}

fn trim_dolby_rpu_nal_payload(payload: &[u8]) -> Vec<u8> {
    if payload.len() < 8 {
        return payload.to_vec();
    }
    let ebsp = &payload[2..];
    let positions = dolby_rpu_rbsp_positions_from_ebsp(ebsp);
    let rbsp: Vec<u8> = positions.iter().map(|&position| ebsp[position]).collect();
    let valid_rbsp_end = find_valid_dolby_rpu_rbsp_end(&rbsp);
    if valid_rbsp_end == 0 || valid_rbsp_end > positions.len() {
        return payload.to_vec();
    }
    payload[..2 + positions[valid_rbsp_end - 1] + 1].to_vec()
}

fn dolby_rpu_payload_is_crc_valid(payload: &[u8]) -> bool {
    if payload.len() < 10 {
        return false;
    }
    let ebsp = &payload[2..];
    let positions = dolby_rpu_rbsp_positions_from_ebsp(ebsp);
    if positions.len() < 8 {
        return false;
    }
    let rbsp: Vec<u8> = positions.iter().map(|&position| ebsp[position]).collect();
    if rbsp.len() < 8 || rbsp[0] != 0x19 {
        return false;
    }

    for end_index in (6..rbsp.len()).rev() {
        if rbsp[end_index] != 0x80 {
            continue;
        }
        let crc_start = end_index - 4;
        if crc_start <= 1 {
            continue;
        }
        let received_crc = u32::from_be_bytes([
            rbsp[crc_start],
            rbsp[crc_start + 1],
            rbsp[crc_start + 2],
            rbsp[crc_start + 3],
        ]);
        let expected_crc = mpeg_crc32(&rbsp[1..crc_start]);
        if received_crc == expected_crc {
            return true;
        }
    }
    false
}

pub(crate) fn decrypt_dolby_rpu_unit(
    unit: &[u8],
    key: &[u8; 16],
    block_key: &[u8; 16],
) -> Option<Vec<u8>> {
    if hevc_nal_type_from_annexb_unit(unit) != 62 {
        return None;
    }

    let start_code_length = if unit.starts_with(&[0x00, 0x00, 0x00, 0x01]) {
        4
    } else if unit.starts_with(&[0x00, 0x00, 0x01]) {
        3
    } else {
        return None;
    };
    if unit.len() < start_code_length + 2 {
        return None;
    }

    let nal_prefix = &unit[start_code_length..start_code_length + 2];
    let encrypted_source_full = &unit[start_code_length + 2..];
    let mut iv_snapshot = [0u8; 16];
    iv_snapshot[..12].copy_from_slice(&block_key[..12]);
    let mut best_payload: Option<Vec<u8>> = None;

    for tail_drop in [4usize, 0, 2, 1, 3, 5, 6, 7, 8, 12, 16] {
        let encrypted_end = encrypted_source_full.len().saturating_sub(tail_drop);
        let encrypted_source = &encrypted_source_full[..encrypted_end];
        let mut candidate = Vec::with_capacity(2 + encrypted_source.len());
        candidate.extend_from_slice(nal_prefix);
        if !encrypted_source.is_empty() {
            candidate.extend_from_slice(&decrypt_es_sparse_stripped_with_padding(
                encrypted_source,
                key,
                &iv_snapshot,
            ));
        }
        candidate = trim_dolby_rpu_nal_payload(&candidate);
        if best_payload.is_none() {
            best_payload = Some(candidate.clone());
        }
        if dolby_rpu_payload_is_crc_valid(&candidate) {
            let mut result = vec![0x00, 0x00, 0x00, 0x01];
            result.extend_from_slice(&candidate);
            return Some(result);
        }
    }

    let mut result = vec![0x00, 0x00, 0x00, 0x01];
    result.extend_from_slice(best_payload.as_deref().unwrap_or(unit));
    Some(result)
}

pub(crate) fn is_valid_dolby_rpu_unit(
    unit: &[u8],
    key: &[u8; 16],
    block_key: &[u8; 16],
) -> bool {
    let Some(decrypted) = decrypt_dolby_rpu_unit(unit, key, block_key) else {
        return false;
    };

    let start_code_length = if decrypted.starts_with(&[0x00, 0x00, 0x00, 0x01]) {
        4
    } else if decrypted.starts_with(&[0x00, 0x00, 0x01]) {
        3
    } else {
        return false;
    };

    dolby_rpu_payload_is_crc_valid(&decrypted[start_code_length..])
}
