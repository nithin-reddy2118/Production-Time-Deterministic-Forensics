//! CRC32 (IEEE 802.3 polynomial, the same variant used by gzip/PNG/zlib),
//! implemented locally rather than pulling in `crc32fast`. Rationale: this
//! crate sits on the throughput-critical storage write path (root
//! `Cargo.toml` dependency policy), and a table-driven CRC32 is ~30 lines
//! of well-understood, easily-tested code — not worth a dependency for.
//! If profiling later shows this is a bottleneck, swapping in a
//! SIMD-accelerated crate behind the same `crc32` function signature is a
//! one-file change, not a redesign.

/// Standard CRC-32/ISO-HDLC lookup table, generated once at first use.
fn table() -> &'static [u32; 256] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        let mut i = 0u32;
        while i < 256 {
            let mut c = i;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            table[i as usize] = c;
            i += 1;
        }
        table
    })
}

/// Compute the CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    let table = table();
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let idx = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = table[idx] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_known_crc() {
        // The CRC-32 of an empty byte string is 0 by definition of the
        // algorithm (well-known reference value).
        assert_eq!(crc32(b""), 0x0000_0000);
    }

    #[test]
    fn known_reference_vector_check_123456789() {
        // "123456789" -> 0xCBF43926 is the standard CRC-32/ISO-HDLC check
        // value used to validate implementations of this exact variant.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn different_inputs_produce_different_checksums() {
        assert_ne!(crc32(b"hello"), crc32(b"hellp"));
    }

    #[test]
    fn checksum_is_deterministic() {
        let data = b"the quick brown fox jumps over the lazy dog";
        assert_eq!(crc32(data), crc32(data));
    }
}
