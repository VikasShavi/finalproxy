use flate2::Decompress;
use flate2::FlushDecompress;
fn parse_client_frame(frame_bytes: &[u8]) -> (u8, Vec<u8>) {
    let first_byte = frame_bytes[0];
    let opcode = first_byte & 0x0F;

    let second_byte = frame_bytes[1];
    let is_masked = (second_byte >> 7) & 1;
    let payload_length = (second_byte & 0x7F) as usize;

    let header_length = 2 + if is_masked == 1 { 4 } else { 0 };
    let mut masking_key: &[u8] = b"";
    if is_masked == 1 {
        masking_key = &frame_bytes[2..6]
    };

    let masked_payload = &frame_bytes[header_length..header_length + payload_length];
    let mut unmasked_payload: Vec<u8>;
    if is_masked == 1 {
        unmasked_payload = masked_payload.iter().enumerate().map(|(i, &b)| b ^ masking_key[i % 4]).collect()
    } else {
        unmasked_payload = masked_payload.to_vec()
    };

    (opcode, unmasked_payload)
}


pub fn decode_client_ws_frame(decompressor: &mut Decompress, data: &[u8], compressed: bool) -> Option<String> {
    let flush_marker: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

    if data.len() < 6 {
        return None;
    }

    let (opcode, mut payload) = parse_client_frame(data);

    if opcode >= 0x8 {
        return None;
    }

    let mut result = Vec::new();

    if compressed {
        if !payload.ends_with(&flush_marker) {
            payload.extend_from_slice(&flush_marker);
        }
        let mut out_buf = vec![0; 1024];
        let before = decompressor.total_out();
        decompressor.decompress(&payload, &mut out_buf, FlushDecompress::None).ok()?;
        let after = decompressor.total_out();
        let written = (after - before) as usize;
        result.extend_from_slice(&out_buf[..written]);
    } else {
        result.extend_from_slice(&payload);
    }

    String::from_utf8(result).ok()
}

