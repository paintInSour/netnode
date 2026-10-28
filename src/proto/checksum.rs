//! The 16-bit ones'-complement "internet checksum" (RFC 1071) used by IPv4 and ICMP.

#![forbid(unsafe_code)]

/// Computes the checksum of `data`.
///
/// Computed over data whose checksum field is zero, the result is the value
/// to store. Computed over data that already contains a correct checksum,
/// the result is zero, which is how [`is_valid`] checks it.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut words = data.chunks_exact(2);
    for word in &mut words {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let [last] = words.remainder() {
        sum += u32::from(*last) << 8; // an odd trailing byte is padded with zero
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// True when `data` carries a correct checksum.
pub fn is_valid(data: &[u8]) -> bool {
    internet_checksum(data) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ipv4_header() {
        // Example header from Wikipedia's IPv4 checksum article; checksum 0xb861.
        let mut header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
            0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(internet_checksum(&header), 0xb861);
        header[10..12].copy_from_slice(&0xb861u16.to_be_bytes());
        assert!(is_valid(&header));
        header[0] ^= 1;
        assert!(!is_valid(&header));
    }

    #[test]
    fn odd_length() {
        let data = [0x01, 0x02, 0x03];
        // 0x0102 + 0x0300 = 0x0402 -> !0x0402 = 0xfbfd
        assert_eq!(internet_checksum(&data), 0xfbfd);
    }
}
