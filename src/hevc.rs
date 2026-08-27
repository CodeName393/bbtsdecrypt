use crate::crypto::{decrypt_nal_vb, AesBlockEncryptor};
use crate::dolby::decrypt_dolby_rpu_unit;
use crate::hdr::decrypt_hdr_sei_unit;

pub(crate) fn find_start_codes(data: &[u8]) -> Vec<(usize, usize)> {
    let mut starts = Vec::new();
    let mut position = 0usize;
    while position + 3 <= data.len() {
        let mut marker = None;
        let mut i = position;
        while i + 3 <= data.len() {
            if data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0x01 {
                marker = Some(i);
                break;
            }
            i += 1;
        }
        let Some(marker) = marker else {
            break;
        };
        let start = if marker > 0 && data[marker - 1] == 0x00 {
            marker - 1
        } else {
            marker
        };
        let size = if start != marker { 4 } else { 3 };
        if starts.last().map(|x: &(usize, usize)| x.0) != Some(start) {
            starts.push((start, size));
        }
        position = marker + 3;
    }
    starts
}

fn append_generic_decrypted_unit(output: &mut Vec<u8>, decrypted: &[u8], start_size: usize) {
    if start_size == 3 && decrypted.len() >= 4 {
        output.push(0x00);
        output.extend_from_slice(&decrypted[..decrypted.len() - 4]);
    } else {
        output.extend_from_slice(decrypted);
    }
}

pub(crate) fn decrypt_es(
    input_stream: &[u8],
    block_key: &[u8; 16],
    encryptor: &AesBlockEncryptor,
    decryption_key: &[u8; 16],
) -> Vec<u8> {
    let starts = find_start_codes(input_stream);
    if starts.is_empty() {
        return input_stream.to_vec();
    }

    let mut output = Vec::with_capacity(input_stream.len());
    if starts[0].0 > 0 {
        output.extend_from_slice(&input_stream[..starts[0].0]);
    }

    for (index, &(start, start_size)) in starts.iter().enumerate() {
        let end = starts
            .get(index + 1)
            .map(|next| next.0)
            .unwrap_or(input_stream.len());
        let nal = &input_stream[start..end];

        if let Some(rpu_decrypted) = decrypt_dolby_rpu_unit(nal, decryption_key, block_key) {
            output.extend_from_slice(&rpu_decrypted);
            continue;
        }

        let trailer_size = if index + 1 == starts.len() { 4 } else { 2 };

        if let Some(hdr_decrypted) =
            decrypt_hdr_sei_unit(nal, block_key, encryptor, trailer_size)
        {
            output.extend_from_slice(&hdr_decrypted);
            continue;
        }

        let decrypted = decrypt_nal_vb(nal, block_key, encryptor, trailer_size);
        append_generic_decrypted_unit(&mut output, &decrypted, start_size);
    }
    output
}
