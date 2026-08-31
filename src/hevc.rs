use crate::crypto::{decrypt_es_sparse_with_emulation_removal, AesBlockEncryptor};

pub(crate) fn decrypt_pes_normal(
    pes: &[u8],
    stream_type: u8,
    encryptor: &AesBlockEncryptor,
    iv_snap: &[u8; 16],
) -> Vec<u8> {
    if pes.len() < 9 {
        return pes.to_vec();
    }

    let pes_header_len = pes[8] as usize;
    let header_end = 9 + pes_header_len;
    if header_end > pes.len() {
        return pes.to_vec();
    }

    let mut new_pes = Vec::with_capacity(pes.len());
    new_pes.extend_from_slice(&pes[..header_end]);

    let nal_hdr_len = if stream_type == 0x1B { 1 } else { 2 };
    let mut pos_st = header_end;
    let mut i = pos_st;

    while i < pes.len() {
        if i == pes.len() - 1 {
            if pes.len() >= 2 && pes.len() - 2 > pos_st + 3 + nal_hdr_len {
                new_pes.extend_from_slice(&pes[pos_st..pos_st + 3 + nal_hdr_len]);
                let es = &pes[pos_st + 3 + nal_hdr_len..pes.len() - 2];
                if !es.is_empty() {
                    let dec_es = decrypt_es_sparse_with_emulation_removal(es, encryptor, iv_snap);
                    new_pes.extend_from_slice(&dec_es);
                }
                new_pes.extend_from_slice(&pes[pes.len() - 2..]);
            } else {
                new_pes.extend_from_slice(&pes[pos_st..]);
            }
        } else if i + 2 < pes.len() && pes[i] == 0 && pes[i + 1] == 0 && pes[i + 2] == 1 {
            if i != pos_st {
                if i >= 2 && i - 2 > pos_st + 3 + nal_hdr_len {
                    new_pes.extend_from_slice(&pes[pos_st..pos_st + 3 + nal_hdr_len]);

                    let flag = i >= 1 && pes[i - 1] == 0;
                    let (es, trailer) = if flag && i >= 3 {
                        (&pes[pos_st + 3 + nal_hdr_len..i - 3], &pes[i - 3..i])
                    } else if i >= 2 {
                        (&pes[pos_st + 3 + nal_hdr_len..i - 2], &pes[i - 2..i])
                    } else {
                        (&pes[pos_st + 3 + nal_hdr_len..pos_st + 3 + nal_hdr_len], &pes[i..i])
                    };

                    if !es.is_empty() {
                        let dec_es = decrypt_es_sparse_with_emulation_removal(es, encryptor, iv_snap);
                        new_pes.extend_from_slice(&dec_es);
                    }
                    new_pes.extend_from_slice(trailer);
                } else {
                    new_pes.extend_from_slice(&pes[pos_st..i]);
                }
                pos_st = i;
            }
        }
        i += 1;
    }

    new_pes
}
