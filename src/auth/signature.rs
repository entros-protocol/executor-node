//! Decoding of wallet signatures that arrive as hex text.

/// Decodes a 64-byte signature from 128 hex characters of either case.
///
/// Every byte is checked before any slicing. A length check alone is not enough:
/// a string of 128 bytes can hold multi-byte characters, and slicing it two bytes
/// at a time then cuts a character and panics.
pub(crate) fn decode_signature_hex(value: &str) -> Option<[u8; 64]> {
    let bytes = value.as_bytes();
    if bytes.len() != 128 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut output = [0_u8; 64];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Some(output)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => value - b'A' + 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_both_cases() {
        let lower = "0f".repeat(64);
        let upper = "0F".repeat(64);
        assert_eq!(decode_signature_hex(&lower), Some([0x0f; 64]));
        assert_eq!(decode_signature_hex(&upper), Some([0x0f; 64]));
    }

    #[test]
    fn refuses_other_lengths_and_non_hex() {
        assert_eq!(decode_signature_hex(""), None);
        assert_eq!(decode_signature_hex(&"0".repeat(127)), None);
        assert_eq!(decode_signature_hex(&"0".repeat(129)), None);
        assert_eq!(decode_signature_hex(&"zz".repeat(64)), None);
    }

    /// 128 bytes that are not 128 characters. Slicing by byte offset would panic here.
    #[test]
    fn refuses_a_multi_byte_character_without_panicking() {
        let crafted = format!("a\u{e9}{}", "0".repeat(125));
        assert_eq!(crafted.len(), 128);
        assert_eq!(decode_signature_hex(&crafted), None);
    }
}
