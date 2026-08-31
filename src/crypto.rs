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
    let (kid, key) = value
        .split_once(':')
        .ok_or("Key must be in KID:KEY format (32hex:32hex)")?;

    if key.contains(':') {
        return Err("Key must be in KID:KEY format (32hex:32hex)".into());
    }
    let _ = parse_hex_key(kid, "KID")?;
    parse_hex_key(key, "AES key")
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

pub(crate) fn ctr_inc(counter: &mut [u8; 16]) {
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

pub(crate) fn decrypt_es_sparse_with_emulation_removal(
    es: &[u8],
    encryptor: &AesBlockEncryptor,
    iv_start: &[u8; 16],
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

    let mut counter_iv = *iv_start;
    let mut output = stripped;
    let mut remaining = output.len();
    let mut position = 0usize;
    let mut counter = 0usize;

    while remaining > 0 {
        ctr_inc(&mut counter_iv);
        let mut temporary = counter_iv;
        if remaining <= 16 || counter % 10 == 0 {
            temporary = encryptor.encrypt_block(&temporary);
        }
        let decrypt_length = remaining.min(16);
        for byte_index in 0..decrypt_length {
            output[position + byte_index] ^= temporary[byte_index];
        }
        remaining -= decrypt_length;
        position += 16;
        counter += 1;
    }

    if output.len() != es.len() {
        let diff = es.len().saturating_sub(output.len());
        if diff > 0 {
            output.extend_from_slice(&es[es.len() - diff..]);
        }
    }
    output
}
