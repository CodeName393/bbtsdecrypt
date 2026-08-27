use crate::common::AppResult;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

pub(crate) struct AesBlockEncryptor {
    cipher: Aes128,
}

impl AesBlockEncryptor {
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128::new(GenericArray::from_slice(key)),
        }
    }

    pub(crate) fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut block = GenericArray::clone_from_slice(input);
        self.cipher.encrypt_block(&mut block);
        let mut output = [0u8; 16];
        output.copy_from_slice(&block);
        output
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn parse_hex_key(value: &str, label: &str) -> AppResult<[u8; 16]> {
    let value = value.trim().as_bytes();
    if value.len() != 32 {
        return Err(format!("{label} must be exactly 32 hex characters").into());
    }

    let mut key = [0u8; 16];
    for i in 0..16 {
        let hi = hex_nibble(value[i * 2])
            .ok_or_else(|| format!("{label} must contain only hex characters"))?;
        let lo = hex_nibble(value[i * 2 + 1])
            .ok_or_else(|| format!("{label} must contain only hex characters"))?;
        key[i] = (hi << 4) | lo;
    }
    Ok(key)
}

pub(crate) fn parse_key_spec(value: &str) -> AppResult<[u8; 16]> {
    let value = value.trim();
    if let Some((kid, key)) = value.split_once(':') {
        if key.contains(':') {
            return Err("Key must be either 32hex or 32hex:32hex".into());
        }
        let _ = parse_hex_key(kid, "KID")?;
        return parse_hex_key(key, "AES key");
    }
    parse_hex_key(value, "AES key")
}

pub(crate) fn decode_hex_16(value: &[u8]) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hex_nibble(value[i * 2])?;
        let lo = hex_nibble(value[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

pub(crate) fn decrypt_nal_vb(
    input_stream: &[u8],
    block_key: &[u8; 16],
    encryptor: &AesBlockEncryptor,
    trailer_size: usize,
) -> Vec<u8> {
    let mut loc11 = input_stream.to_vec();
    let mut loc9 = vec![0u8; loc11.len()];
    let mut loc22 = 0usize;
    let mut loc23 = 0usize;

    while loc22 < loc11.len() {
        if loc22 + 3 < loc11.len()
            && loc11[loc22] == 0
            && loc11[loc22 + 1] == 0
            && loc11[loc22 + 2] == 3
            && matches!(loc11[loc22 + 3], 0 | 1 | 2 | 3)
        {
            loc9[loc23] = loc11[loc22];
            loc23 += 1;
            loc9[loc23] = loc11[loc22 + 1];
            loc23 += 1;
            loc9[loc23] = loc11[loc22 + 3];
            loc23 += 1;
            loc22 += 4;
        } else {
            loc9[loc23] = loc11[loc22];
            loc22 += 1;
            loc23 += 1;
        }
    }

    let payload_size = loc23 as isize - 5 - trailer_size as isize;
    if payload_size <= 0 {
        return loc11;
    }
    let payload_size = payload_size as usize;
    let mut loc12 = loc9[5..5 + payload_size].to_vec();
    let block_count = (loc12.len() + 15) / 16;
    let mut loc14 = 0usize;

    for block_index in 1..=block_count {
        let mut loc17 = [0u8; 16];
        loc17[..12].copy_from_slice(&block_key[..12]);
        loc17[12..].copy_from_slice(&(block_index as u32).to_be_bytes());
        if block_index % 10 == 1 || block_index == block_count {
            loc17 = encryptor.encrypt_block(&loc17);
        }
        for &value in &loc17 {
            if loc14 == loc12.len() {
                break;
            }
            loc12[loc14] ^= value;
            loc14 += 1;
        }
    }

    loc11[5..5 + loc12.len()].copy_from_slice(&loc12);
    if trailer_size > 0 {
        let src_start = 5 + loc12.len();
        let src_end = src_start + trailer_size;
        if src_end <= loc9.len() && src_end <= loc11.len() {
            loc11[src_start..src_end].copy_from_slice(&loc9[src_start..src_end]);
        }
    }

    let loc10 = loc11
        .len()
        .saturating_sub(5 + loc12.len() + trailer_size);
    if loc10 > 0 {

        let index = loc11.len() - loc10;
        loc11[index] = 0;
    }
    loc11
}

fn increment_counter(counter: &mut [u8; 16]) {
    let mut carry = 1u16;
    for index in (0..16).rev() {
        let value = counter[index] as u16 + carry;
        counter[index] = (value & 0xff) as u8;
        carry = value >> 8;
        if carry == 0 {
            break;
        }
    }
}

pub(crate) fn decrypt_es_sparse_stripped_with_padding(
    es: &[u8],
    key: &[u8; 16],
    iv_start: &[u8],
) -> Vec<u8> {
    let mut stripped = Vec::with_capacity(es.len());
    let mut index = 0usize;
    while index < es.len() {
        if index + 2 < es.len()
            && es[index] == 0x00
            && es[index + 1] == 0x00
            && es[index + 2] == 0x03
        {
            stripped.extend_from_slice(&[0x00, 0x00]);
            index += 3;
        } else {
            stripped.push(es[index]);
            index += 1;
        }
    }

    let mut counter = [0u8; 16];
    let copy_len = iv_start.len().min(16);
    counter[..copy_len].copy_from_slice(&iv_start[..copy_len]);
    let mut output = stripped;
    let mut remaining = output.len();
    let mut position = 0usize;
    let mut block_index = 0usize;
    let encryptor = AesBlockEncryptor::new(key);

    while remaining > 0 {
        increment_counter(&mut counter);
        let mut temporary = counter;
        if remaining <= 16 || block_index % 10 == 0 {
            temporary = encryptor.encrypt_block(&temporary);
        }
        let decrypt_length = remaining.min(16);
        for byte_index in 0..decrypt_length {
            output[position + byte_index] ^= temporary[byte_index];
        }
        remaining -= decrypt_length;
        position += 16;
        block_index += 1;
    }

    if output.len() != es.len() {
        if output.len() < es.len() {
            let difference = es.len() - output.len();
            output.extend_from_slice(&es[es.len() - difference..]);
        } else {
            output.truncate(es.len());
        }
    }
    output
}
