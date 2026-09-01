pub fn magnitude_to_u128(mag: &[u8]) -> Option<u128> {
    if mag.len() > 16 {
        return None;
    }
    let mut out = 0u128;
    for &b in mag {
        out = (out << 8) | u128::from(b);
    }
    Some(out)
}
