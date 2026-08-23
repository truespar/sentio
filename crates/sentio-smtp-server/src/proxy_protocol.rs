use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

/// Client/server addresses extracted from a PROXY protocol v2 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyInfo {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
}

/// Errors during PROXY protocol v2 parsing.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("invalid PROXY protocol v2 signature")]
    InvalidSignature,
    #[error("unsupported PROXY protocol version: {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported address family/transport: {0:#04x}")]
    UnsupportedFamily(u8),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("address data too short for family")]
    TruncatedAddress,
}

/// The 12-byte PROXY protocol v2 magic signature.
const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Read and parse a PROXY protocol v2 header from the stream.
///
/// Returns the source and destination addresses. For LOCAL commands (health
/// checks), returns loopback addresses.
pub async fn read_proxy_header<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<ProxyInfo, ProxyError> {
    // Read the 16-byte fixed header: 12 sig + ver/cmd + fam + 2-byte len
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await?;

    // Verify signature
    if header[..12] != SIGNATURE {
        return Err(ProxyError::InvalidSignature);
    }

    let ver_cmd = header[12];
    let version = (ver_cmd >> 4) & 0x0F;
    let command = ver_cmd & 0x0F;

    if version != 2 {
        return Err(ProxyError::UnsupportedVersion(version));
    }

    let family = header[13];
    let addr_len = u16::from_be_bytes([header[14], header[15]]) as usize;

    // Read the address data
    let mut addr_data = vec![0u8; addr_len];
    if addr_len > 0 {
        stream.read_exact(&mut addr_data).await?;
    }

    // LOCAL command: health check, no real addresses
    if command == 0 {
        return Ok(ProxyInfo {
            src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            dst_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        });
    }

    // PROXY command (command == 1)
    let addr_family = (family >> 4) & 0x0F;
    let _transport = family & 0x0F; // 1=TCP, 2=UDP

    match addr_family {
        // AF_INET (IPv4)
        1 => {
            if addr_data.len() < 12 {
                return Err(ProxyError::TruncatedAddress);
            }
            let src_ip = Ipv4Addr::new(addr_data[0], addr_data[1], addr_data[2], addr_data[3]);
            let dst_ip = Ipv4Addr::new(addr_data[4], addr_data[5], addr_data[6], addr_data[7]);
            let src_port = u16::from_be_bytes([addr_data[8], addr_data[9]]);
            let dst_port = u16::from_be_bytes([addr_data[10], addr_data[11]]);
            Ok(ProxyInfo {
                src_addr: SocketAddr::new(IpAddr::V4(src_ip), src_port),
                dst_addr: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
            })
        }
        // AF_INET6 (IPv6)
        2 => {
            if addr_data.len() < 36 {
                return Err(ProxyError::TruncatedAddress);
            }
            let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&addr_data[0..16]).unwrap());
            let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&addr_data[16..32]).unwrap());
            let src_port = u16::from_be_bytes([addr_data[32], addr_data[33]]);
            let dst_port = u16::from_be_bytes([addr_data[34], addr_data[35]]);
            Ok(ProxyInfo {
                src_addr: SocketAddr::new(IpAddr::V6(src_ip), src_port),
                dst_addr: SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
            })
        }
        _ => Err(ProxyError::UnsupportedFamily(family)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn build_v2_header(command: u8, family: u8, addr_data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&SIGNATURE);
        buf.push(0x20 | command); // version 2 + command
        buf.push(family);
        let len = addr_data.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(addr_data);
        buf
    }

    #[tokio::test]
    async fn parse_ipv4_proxy() {
        // src: 192.168.1.1:12345, dst: 10.0.0.1:25
        let mut addr = Vec::new();
        addr.extend_from_slice(&[192, 168, 1, 1]); // src IP
        addr.extend_from_slice(&[10, 0, 0, 1]); // dst IP
        addr.extend_from_slice(&12345u16.to_be_bytes()); // src port
        addr.extend_from_slice(&25u16.to_be_bytes()); // dst port

        let data = build_v2_header(1, 0x11, &addr); // AF_INET + STREAM
        let mut cursor = Cursor::new(data);
        let info = read_proxy_header(&mut cursor).await.unwrap();

        assert_eq!(
            info.src_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345)
        );
        assert_eq!(
            info.dst_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 25)
        );
    }

    #[tokio::test]
    async fn parse_ipv6_proxy() {
        let mut addr = Vec::new();
        // src: ::1
        addr.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // dst: ::2
        addr.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        addr.extend_from_slice(&4321u16.to_be_bytes());
        addr.extend_from_slice(&587u16.to_be_bytes());

        let data = build_v2_header(1, 0x21, &addr); // AF_INET6 + STREAM
        let mut cursor = Cursor::new(data);
        let info = read_proxy_header(&mut cursor).await.unwrap();

        assert_eq!(info.src_addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(info.src_addr.port(), 4321);
        assert_eq!(info.dst_addr.port(), 587);
    }

    #[tokio::test]
    async fn parse_local_command() {
        let data = build_v2_header(0, 0x00, &[]);
        let mut cursor = Cursor::new(data);
        let info = read_proxy_header(&mut cursor).await.unwrap();

        assert_eq!(info.src_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(info.dst_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn invalid_signature() {
        let mut data = vec![0u8; 16];
        data[0] = 0xFF; // corrupt signature
        let mut cursor = Cursor::new(data);
        let err = read_proxy_header(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ProxyError::InvalidSignature));
    }

    #[tokio::test]
    async fn unsupported_version() {
        let mut data = Vec::new();
        data.extend_from_slice(&SIGNATURE);
        data.push(0x31); // version 3
        data.push(0x00);
        data.extend_from_slice(&0u16.to_be_bytes());
        let mut cursor = Cursor::new(data);
        let err = read_proxy_header(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ProxyError::UnsupportedVersion(3)));
    }

    #[tokio::test]
    async fn truncated_ipv4_address() {
        let addr = vec![0u8; 6]; // only 6 bytes, need 12
        let data = build_v2_header(1, 0x11, &addr);
        let mut cursor = Cursor::new(data);
        let err = read_proxy_header(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ProxyError::TruncatedAddress));
    }

    #[tokio::test]
    async fn truncated_ipv6_address() {
        let addr = vec![0u8; 20]; // only 20 bytes, need 36
        let data = build_v2_header(1, 0x21, &addr);
        let mut cursor = Cursor::new(data);
        let err = read_proxy_header(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ProxyError::TruncatedAddress));
    }

    #[tokio::test]
    async fn unsupported_family() {
        let addr = vec![0u8; 4];
        let data = build_v2_header(1, 0x31, &addr); // AF_UNIX
        let mut cursor = Cursor::new(data);
        let err = read_proxy_header(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ProxyError::UnsupportedFamily(_)));
    }
}
