use crate::misc::Builder;

pub fn wrap_payload(payload: Vec<u8>) -> Vec<u8> {
    // packet length + padding
    let mut padding = ((4 + 1 + payload.len()) % 8) as u8;
    if padding < 4 {
        padding = 8 - padding;
    } else {
        padding = 8 + (8 - padding);
    }

    Builder::new()
        // padding field + payload
        .write_u32(1 + payload.len() as u32 + padding as u32)
        .write_u8(padding)
        .write_vec(payload)
        .write_vec(vec![0; padding as usize])
        .build()
}