//! Bitcoin-style CompactSize integers.

/// Append `n` as a CompactSize integer.
///
/// The casts below are bounds-checked by the branch they sit in; the workspace
/// denies truncating casts, so each one is justified rather than blanket-allowed.
#[allow(
    clippy::cast_possible_truncation,
    reason = "each cast is guarded by the range check of its own branch"
)]
pub fn write_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// Append `bytes` prefixed by its CompactSize length (a "varslice").
pub fn write_var_slice(buf: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(n: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, n);
        buf
    }

    #[test]
    fn encodes_each_size_class_at_its_boundary() {
        assert_eq!(encode(0), vec![0x00]);
        assert_eq!(encode(0xfc), vec![0xfc]);
        assert_eq!(encode(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(encode(0xffff), vec![0xfd, 0xff, 0xff]);
        assert_eq!(encode(0x1_0000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(encode(0xffff_ffff), vec![0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            encode(0x1_0000_0000),
            vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn var_slice_is_length_then_bytes() {
        let mut buf = Vec::new();
        write_var_slice(&mut buf, &[0xde, 0xad]);
        assert_eq!(buf, vec![0x02, 0xde, 0xad]);
    }
}
