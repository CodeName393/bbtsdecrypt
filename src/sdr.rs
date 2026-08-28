use crate::common::VideoMode;

const NAL_SPS: u8 = 33;

#[derive(Clone, Copy, Debug)]
pub(crate) struct SpsInfo {
    pub(crate) colour_primaries: Option<u8>,
    pub(crate) transfer_characteristics: Option<u8>,
    pub(crate) matrix_coeffs: Option<u8>,
}

#[derive(Clone, Copy, Debug)]
struct VuiLocation {
    vui_present_flag_pos: usize,
    vui_present: bool,

    video_signal_present_flag_pos: Option<usize>,
    video_signal_present: bool,
    video_format_pos: Option<usize>,
    full_range_pos: Option<usize>,
    colour_description_flag_pos: Option<usize>,
    colour_description_present: bool,
    colour_primaries_pos: Option<usize>,
    transfer_characteristics_pos: Option<usize>,
    matrix_coeffs_pos: Option<usize>,
    colour_primaries_value: Option<u8>,
    transfer_characteristics_value: Option<u8>,
    matrix_coeffs_value: Option<u8>,

    chroma_loc_info_present_flag_pos: Option<usize>,
    chroma_loc_info_present: bool,
    chroma_top_ue_start: Option<usize>,
    chroma_top_ue_end: Option<usize>,
    chroma_bottom_ue_start: Option<usize>,
    chroma_bottom_ue_end: Option<usize>,
}

struct BitReader<'a> {
    data: &'a [u8],
    bitpos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bitpos: 0 }
    }

    fn read_bits(&mut self, n: usize) -> Option<u64> {
        if n > 64 || self.bitpos.checked_add(n)? > self.data.len() * 8 {
            return None;
        }
        let mut value = 0u64;
        for _ in 0..n {
            let byte_index = self.bitpos >> 3;
            let bit_index = 7 - (self.bitpos & 7);
            value = (value << 1) | (((self.data[byte_index] >> bit_index) & 1) as u64);
            self.bitpos += 1;
        }
        Some(value)
    }

    fn read_bool(&mut self) -> Option<bool> {
        Some(self.read_bits(1)? != 0)
    }

    fn read_ue(&mut self) -> Option<u32> {
        let mut zeros = 0usize;
        loop {
            if self.read_bits(1)? != 0 {
                break;
            }
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        if zeros == 0 {
            return Some(0);
        }
        let info = self.read_bits(zeros)? as u32;
        Some(((1u32 << zeros) - 1).checked_add(info)?)
    }

    fn read_se(&mut self) -> Option<i32> {
        let code_num = self.read_ue()?;
        if code_num & 1 == 0 {
            Some(-((code_num / 2) as i32))
        } else {
            Some(((code_num + 1) / 2) as i32)
        }
    }
}

fn skip_profile_tier_level(br: &mut BitReader<'_>, max_sub_layers_minus1: usize) -> Option<()> {
    br.read_bits(2)?;
    br.read_bits(1)?;
    br.read_bits(5)?;
    br.read_bits(32)?;
    br.read_bits(48)?;
    br.read_bits(8)?;

    let mut profile_present = vec![false; max_sub_layers_minus1];
    let mut level_present = vec![false; max_sub_layers_minus1];

    for i in 0..max_sub_layers_minus1 {
        profile_present[i] = br.read_bool()?;
        level_present[i] = br.read_bool()?;
    }

    if max_sub_layers_minus1 > 0 {
        for _ in max_sub_layers_minus1..8 {
            br.read_bits(2)?;
        }
    }

    for i in 0..max_sub_layers_minus1 {
        if profile_present[i] {
            br.read_bits(2)?;
            br.read_bits(1)?;
            br.read_bits(5)?;
            br.read_bits(32)?;
            br.read_bits(48)?;
        }
        if level_present[i] {
            br.read_bits(8)?;
        }
    }

    Some(())
}

fn skip_scaling_list_data(br: &mut BitReader<'_>) -> Option<()> {
    for size_id in 0usize..4 {
        let step = if size_id == 3 { 3 } else { 1 };
        let mut matrix_id = 0usize;
        while matrix_id < 6 {
            let pred_mode_flag = br.read_bool()?;
            if !pred_mode_flag {
                br.read_ue()?;
            } else {
                let coef_num = 64usize.min(1usize << (4 + (size_id << 1)));
                if size_id > 1 {
                    br.read_se()?;
                }
                for _ in 0..coef_num {
                    br.read_se()?;
                }
            }
            matrix_id += step;
        }
    }
    Some(())
}

fn skip_short_term_ref_pic_set(
    br: &mut BitReader<'_>,
    st_rps_idx: usize,
    num_delta_pocs: &mut Vec<u32>,
) -> Option<()> {
    let inter_ref_pic_set_prediction_flag = if st_rps_idx == 0 {
        false
    } else {
        br.read_bool()?
    };

    if inter_ref_pic_set_prediction_flag {
        let ref_rps_idx = st_rps_idx.checked_sub(1)?;
        let ndp = *num_delta_pocs.get(ref_rps_idx)?;

        br.read_bool()?;
        br.read_ue()?;

        let mut current_num_delta_pocs = 0u32;
        for _ in 0..=ndp {
            let used_by_curr_pic_flag = br.read_bool()?;
            let use_delta_flag = if used_by_curr_pic_flag {
                true
            } else {
                br.read_bool()?
            };
            if used_by_curr_pic_flag || use_delta_flag {
                current_num_delta_pocs = current_num_delta_pocs.checked_add(1)?;
            }
        }
        num_delta_pocs.push(current_num_delta_pocs);
    } else {
        let num_negative_pics = br.read_ue()?;
        let num_positive_pics = br.read_ue()?;

        for _ in 0..num_negative_pics {
            br.read_ue()?;
            br.read_bool()?;
        }
        for _ in 0..num_positive_pics {
            br.read_ue()?;
            br.read_bool()?;
        }

        num_delta_pocs.push(num_negative_pics.checked_add(num_positive_pics)?);
    }

    Some(())
}

fn locate_vui(rbsp: &[u8]) -> Option<VuiLocation> {
    let mut br = BitReader::new(rbsp);

    br.read_bits(4)?;
    let max_sub_layers_minus1 = br.read_bits(3)? as usize;
    br.read_bits(1)?;

    skip_profile_tier_level(&mut br, max_sub_layers_minus1)?;

    br.read_ue()?;
    let chroma_format_idc = br.read_ue()?;
    if chroma_format_idc == 3 {
        br.read_bits(1)?;
    }

    br.read_ue()?;
    br.read_ue()?;

    if br.read_bool()? {
        br.read_ue()?;
        br.read_ue()?;
        br.read_ue()?;
        br.read_ue()?;
    }

    br.read_ue()?;
    br.read_ue()?;
    let log2_max_pic_order_cnt_lsb_minus4 = br.read_ue()? as usize;

    let sub_layer_ordering_info_present = br.read_bool()?;
    let start = if sub_layer_ordering_info_present {
        0
    } else {
        max_sub_layers_minus1
    };
    for _ in start..=max_sub_layers_minus1 {
        br.read_ue()?;
        br.read_ue()?;
        br.read_ue()?;
    }

    br.read_ue()?;
    br.read_ue()?;
    br.read_ue()?;
    br.read_ue()?;
    br.read_ue()?;
    br.read_ue()?;

    if br.read_bool()? {
        if br.read_bool()? {
            skip_scaling_list_data(&mut br)?;
        }
    }

    br.read_bool()?;
    br.read_bool()?;

    if br.read_bool()? {
        br.read_bits(4)?;
        br.read_bits(4)?;
        br.read_ue()?;
        br.read_ue()?;
        br.read_bool()?;
    }

    let num_short_term_ref_pic_sets = br.read_ue()? as usize;
    let mut num_delta_pocs = Vec::with_capacity(num_short_term_ref_pic_sets);
    for idx in 0..num_short_term_ref_pic_sets {
        skip_short_term_ref_pic_set(&mut br, idx, &mut num_delta_pocs)?;
    }

    if br.read_bool()? {
        let num_long_term_ref_pics_sps = br.read_ue()?;
        let poc_lsb_bits = log2_max_pic_order_cnt_lsb_minus4.checked_add(4)?;
        for _ in 0..num_long_term_ref_pics_sps {
            br.read_bits(poc_lsb_bits)?;
            br.read_bool()?;
        }
    }

    br.read_bool()?;
    br.read_bool()?;

    let vui_present_flag_pos = br.bitpos;
    let vui_present = br.read_bool()?;

    if !vui_present {
        return Some(VuiLocation {
            vui_present_flag_pos,
            vui_present,
            video_signal_present_flag_pos: None,
            video_signal_present: false,
            video_format_pos: None,
            full_range_pos: None,
            colour_description_flag_pos: None,
            colour_description_present: false,
            colour_primaries_pos: None,
            transfer_characteristics_pos: None,
            matrix_coeffs_pos: None,
            colour_primaries_value: None,
            transfer_characteristics_value: None,
            matrix_coeffs_value: None,
            chroma_loc_info_present_flag_pos: None,
            chroma_loc_info_present: false,
            chroma_top_ue_start: None,
            chroma_top_ue_end: None,
            chroma_bottom_ue_start: None,
            chroma_bottom_ue_end: None,
        });
    }

    if br.read_bool()? {
        let aspect_ratio_idc = br.read_bits(8)?;
        if aspect_ratio_idc == 255 {
            br.read_bits(16)?;
            br.read_bits(16)?;
        }
    }

    if br.read_bool()? {
        br.read_bool()?;
    }

    let video_signal_present_flag_pos = br.bitpos;
    let video_signal_present = br.read_bool()?;

    let mut video_format_pos = None;
    let mut full_range_pos = None;
    let mut colour_description_flag_pos = None;
    let mut colour_description_present = false;
    let mut colour_primaries_pos = None;
    let mut transfer_characteristics_pos = None;
    let mut matrix_coeffs_pos = None;
    let mut colour_primaries_value = None;
    let mut transfer_characteristics_value = None;
    let mut matrix_coeffs_value = None;

    if video_signal_present {
        video_format_pos = Some(br.bitpos);
        br.read_bits(3)?;

        full_range_pos = Some(br.bitpos);
        br.read_bool()?;

        colour_description_flag_pos = Some(br.bitpos);
        colour_description_present = br.read_bool()?;

        if colour_description_present {
            colour_primaries_pos = Some(br.bitpos);
            colour_primaries_value = Some(br.read_bits(8)? as u8);
            transfer_characteristics_pos = Some(br.bitpos);
            transfer_characteristics_value = Some(br.read_bits(8)? as u8);
            matrix_coeffs_pos = Some(br.bitpos);
            matrix_coeffs_value = Some(br.read_bits(8)? as u8);
        }
    }

    let chroma_loc_info_present_flag_pos = br.bitpos;
    let chroma_loc_info_present = br.read_bool()?;

    let mut chroma_top_ue_start = None;
    let mut chroma_top_ue_end = None;
    let mut chroma_bottom_ue_start = None;
    let mut chroma_bottom_ue_end = None;

    if chroma_loc_info_present {
        chroma_top_ue_start = Some(br.bitpos);
        br.read_ue()?;
        chroma_top_ue_end = Some(br.bitpos);

        chroma_bottom_ue_start = Some(br.bitpos);
        br.read_ue()?;
        chroma_bottom_ue_end = Some(br.bitpos);
    }

    Some(VuiLocation {
        vui_present_flag_pos,
        vui_present,
        video_signal_present_flag_pos: Some(video_signal_present_flag_pos),
        video_signal_present,
        video_format_pos,
        full_range_pos,
        colour_description_flag_pos,
        colour_description_present,
        colour_primaries_pos,
        transfer_characteristics_pos,
        matrix_coeffs_pos,
        colour_primaries_value,
        transfer_characteristics_value,
        matrix_coeffs_value,
        chroma_loc_info_present_flag_pos: Some(chroma_loc_info_present_flag_pos),
        chroma_loc_info_present,
        chroma_top_ue_start,
        chroma_top_ue_end,
        chroma_bottom_ue_start,
        chroma_bottom_ue_end,
    })
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
    let start = start_code_length(unit)?;
    Some((unit.get(start)? >> 1) & 0x3f)
}

fn ebsp_to_rbsp(ebsp: &[u8]) -> Vec<u8> {
    let mut rbsp = Vec::with_capacity(ebsp.len());
    let mut zeros = 0usize;

    for &value in ebsp {
        if zeros >= 2 && value == 0x03 {
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

fn rbsp_to_bits(rbsp: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(rbsp.len() * 8);
    for &byte in rbsp {
        for shift in (0..8).rev() {
            bits.push((byte >> shift) & 1);
        }
    }
    bits
}

fn bits_to_rbsp(bits: &[u8]) -> Vec<u8> {
    let padded_len = (bits.len() + 7) & !7;
    let mut output = Vec::with_capacity(padded_len / 8);
    let mut index = 0usize;

    while index < padded_len {
        let mut value = 0u8;
        for bit_index in 0..8 {
            value <<= 1;
            let source_index = index + bit_index;
            if source_index < bits.len() {
                value |= bits[source_index] & 1;
            }
        }
        output.push(value);
        index += 8;
    }

    output
}

fn value_bits(value: u32, width: usize) -> Vec<u8> {
    let mut bits = Vec::with_capacity(width);
    for shift in (0..width).rev() {
        bits.push(((value >> shift) & 1) as u8);
    }
    bits
}

fn ue_to_bits(value: u32) -> Vec<u8> {
    let code_num = value.saturating_add(1);
    let bit_len = (32 - code_num.leading_zeros()) as usize;
    let mut bits = vec![0; bit_len.saturating_sub(1)];
    bits.extend(value_bits(code_num, bit_len));
    bits
}

fn set_bit(bits: &mut [u8], position: usize, value: u8) -> Option<()> {
    *bits.get_mut(position)? = value & 1;
    Some(())
}

fn set_bits(bits: &mut [u8], position: usize, width: usize, value: u32) -> Option<()> {
    if position.checked_add(width)? > bits.len() {
        return None;
    }
    for i in 0..width {
        bits[position + i] = ((value >> (width - 1 - i)) & 1) as u8;
    }
    Some(())
}

fn minimal_vui_bits(mode: VideoMode) -> Vec<u8> {
    let mut bits = Vec::new();

    bits.push(0);
    bits.push(0);

    if mode == VideoMode::Sdr {
        bits.push(1);
        bits.extend(value_bits(5, 3));
        bits.push(0);
        bits.push(1);
        bits.extend(value_bits(1, 8));
        bits.extend(value_bits(1, 8));
        bits.extend(value_bits(1, 8));
    } else {
        bits.push(0);
    }

    bits.push(1);
    let type2 = ue_to_bits(2);
    bits.extend_from_slice(&type2);
    bits.extend_from_slice(&type2);

    bits.push(0);
    bits.push(0);
    bits.push(0);
    bits.push(0);
    bits.push(0);
    bits.push(0);

    bits
}

fn rebuild_unit(unit: &[u8], rbsp: &[u8]) -> Option<Vec<u8>> {
    let start = start_code_length(unit)?;
    if unit.len() < start + 2 {
        return None;
    }
    let header_end = start + 2;
    let new_ebsp = rbsp_to_ebsp(rbsp);
    let mut output = Vec::with_capacity(header_end + new_ebsp.len());
    output.extend_from_slice(&unit[..header_end]);
    output.extend_from_slice(&new_ebsp);
    Some(output)
}

fn patch_sdr_colorimetry(rbsp: &[u8]) -> Option<Vec<u8>> {
    let loc = locate_vui(rbsp)?;
    let mut bits = rbsp_to_bits(rbsp);

    if !loc.vui_present {
        set_bit(&mut bits, loc.vui_present_flag_pos, 1)?;
        let insertion = minimal_vui_bits(VideoMode::Sdr);
        bits.splice(loc.vui_present_flag_pos + 1..loc.vui_present_flag_pos + 1, insertion);
        return Some(bits_to_rbsp(&bits));
    }

    if !loc.video_signal_present {
        let flag_pos = loc.video_signal_present_flag_pos?;
        set_bit(&mut bits, flag_pos, 1)?;

        let mut insertion = Vec::new();
        insertion.extend(value_bits(5, 3));
        insertion.push(0);
        insertion.push(1);
        insertion.extend(value_bits(1, 8));
        insertion.extend(value_bits(1, 8));
        insertion.extend(value_bits(1, 8));
        bits.splice(flag_pos + 1..flag_pos + 1, insertion);
        return Some(bits_to_rbsp(&bits));
    }

    if let Some(position) = loc.video_format_pos {
        set_bits(&mut bits, position, 3, 5)?;
    }
    if let Some(position) = loc.full_range_pos {
        set_bit(&mut bits, position, 0)?;
    }

    let colour_flag_pos = loc.colour_description_flag_pos?;
    if loc.colour_description_present {
        set_bits(&mut bits, loc.colour_primaries_pos?, 8, 1)?;
        set_bits(&mut bits, loc.transfer_characteristics_pos?, 8, 1)?;
        set_bits(&mut bits, loc.matrix_coeffs_pos?, 8, 1)?;
    } else {
        set_bit(&mut bits, colour_flag_pos, 1)?;
        let mut insertion = Vec::with_capacity(24);
        insertion.extend(value_bits(1, 8));
        insertion.extend(value_bits(1, 8));
        insertion.extend(value_bits(1, 8));
        bits.splice(colour_flag_pos + 1..colour_flag_pos + 1, insertion);
    }

    Some(bits_to_rbsp(&bits))
}

fn patch_chroma_type2(rbsp: &[u8], mode: VideoMode) -> Option<Vec<u8>> {
    let loc = locate_vui(rbsp)?;
    let mut bits = rbsp_to_bits(rbsp);

    if !loc.vui_present {
        set_bit(&mut bits, loc.vui_present_flag_pos, 1)?;
        let insertion = minimal_vui_bits(mode);
        bits.splice(loc.vui_present_flag_pos + 1..loc.vui_present_flag_pos + 1, insertion);
        return Some(bits_to_rbsp(&bits));
    }

    let flag_pos = loc.chroma_loc_info_present_flag_pos?;
    let new_ue = ue_to_bits(2);

    if !loc.chroma_loc_info_present {
        set_bit(&mut bits, flag_pos, 1)?;
        let mut insertion = Vec::with_capacity(new_ue.len() * 2);
        insertion.extend_from_slice(&new_ue);
        insertion.extend_from_slice(&new_ue);
        bits.splice(flag_pos + 1..flag_pos + 1, insertion);
        return Some(bits_to_rbsp(&bits));
    }

    let b0 = loc.chroma_bottom_ue_start?;
    let b1 = loc.chroma_bottom_ue_end?;
    bits.splice(b0..b1, new_ue.iter().copied());

    let t0 = loc.chroma_top_ue_start?;
    let t1 = loc.chroma_top_ue_end?;
    bits.splice(t0..t1, new_ue.iter().copied());

    Some(bits_to_rbsp(&bits))
}

pub(crate) fn inspect_sps(unit: &[u8]) -> Option<SpsInfo> {
    let start = start_code_length(unit)?;
    if hevc_nal_type(unit)? != NAL_SPS || unit.len() < start + 3 {
        return None;
    }
    let rbsp = ebsp_to_rbsp(unit.get(start + 2..)?);
    let loc = locate_vui(&rbsp)?;
    Some(SpsInfo {
        colour_primaries: loc.colour_primaries_value,
        transfer_characteristics: loc.transfer_characteristics_value,
        matrix_coeffs: loc.matrix_coeffs_value,
    })
}

pub(crate) fn patch_sps_signaling(unit: &[u8], mode: VideoMode) -> Option<Vec<u8>> {
    let start = start_code_length(unit)?;
    if hevc_nal_type(unit)? != NAL_SPS || unit.len() < start + 3 {
        return None;
    }

    let rbsp_original = ebsp_to_rbsp(unit.get(start + 2..)?);
    let rbsp_after_color = if mode == VideoMode::Sdr {
        patch_sdr_colorimetry(&rbsp_original)?
    } else {
        rbsp_original
    };
    let rbsp_final = patch_chroma_type2(&rbsp_after_color, mode)?;
    rebuild_unit(unit, &rbsp_final)
}
