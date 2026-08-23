use std::net::IpAddr;

use crate::response::SmtpResponse;

/// Parameters parsed from an XCLIENT command (Postfix extension).
///
/// XCLIENT lets a trusted upstream proxy pass the real client metadata
/// to the downstream MTA at the SMTP session level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XClientParams {
    pub addr: Option<IpAddr>,
    pub name: Option<String>,
    pub helo: Option<String>,
    pub login: Option<String>,
    pub port: Option<u16>,
}

/// Parse the argument portion of an `XCLIENT` command line.
///
/// Format: `XCLIENT ADDR=1.2.3.4 NAME=client.example.com HELO=ehlo.example.com`
///
/// Attributes are space-separated `KEY=VALUE` pairs with case-insensitive keys.
/// Values of `[UNAVAILABLE]` and `[TEMPUNAVAIL]` are treated as `None`.
pub fn parse_xclient(rest: &str) -> Result<XClientParams, SmtpResponse> {
    if rest.is_empty() {
        return Err(SmtpResponse::syntax_error());
    }

    let mut addr = None;
    let mut name = None;
    let mut helo = None;
    let mut login = None;
    let mut port = None;

    for pair in rest.split_whitespace() {
        let eq_pos = pair.find('=').ok_or_else(SmtpResponse::syntax_error)?;
        let key = &pair[..eq_pos];
        let value = &pair[eq_pos + 1..];

        if is_unavailable(value) {
            continue;
        }

        match key.to_ascii_uppercase().as_str() {
            "ADDR" => {
                addr = Some(
                    value
                        .parse::<IpAddr>()
                        .map_err(|_| SmtpResponse::syntax_error())?,
                );
            }
            "NAME" => {
                name = Some(value.to_string());
            }
            "HELO" => {
                helo = Some(value.to_string());
            }
            "LOGIN" => {
                login = Some(value.to_string());
            }
            "PORT" => {
                port = Some(
                    value
                        .parse::<u16>()
                        .map_err(|_| SmtpResponse::syntax_error())?,
                );
            }
            _ => {
                // Unknown attributes are silently ignored
            }
        }
    }

    Ok(XClientParams {
        addr,
        name,
        helo,
        login,
        port,
    })
}

/// Check if a value represents "unavailable" per Postfix XCLIENT convention.
fn is_unavailable(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper == "[UNAVAILABLE]" || upper == "[TEMPUNAVAIL]"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parse_all_attributes() {
        let params = parse_xclient(
            "ADDR=1.2.3.4 NAME=client.example.com HELO=ehlo.example.com LOGIN=user1 PORT=12345",
        )
        .unwrap();
        assert_eq!(params.addr, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(params.name.as_deref(), Some("client.example.com"));
        assert_eq!(params.helo.as_deref(), Some("ehlo.example.com"));
        assert_eq!(params.login.as_deref(), Some("user1"));
        assert_eq!(params.port, Some(12345));
    }

    #[test]
    fn parse_addr_only() {
        let params = parse_xclient("ADDR=10.0.0.1").unwrap();
        assert_eq!(params.addr, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(params.name, None);
        assert_eq!(params.helo, None);
        assert_eq!(params.login, None);
        assert_eq!(params.port, None);
    }

    #[test]
    fn parse_ipv6() {
        let params = parse_xclient("ADDR=2001:db8::1").unwrap();
        assert_eq!(
            params.addr,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        );
    }

    #[test]
    fn parse_ipv6_loopback() {
        let params = parse_xclient("ADDR=::1").unwrap();
        assert_eq!(params.addr, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn unavailable_treated_as_none() {
        let params = parse_xclient("ADDR=[UNAVAILABLE] NAME=[TEMPUNAVAIL]").unwrap();
        assert_eq!(params.addr, None);
        assert_eq!(params.name, None);
    }

    #[test]
    fn unavailable_case_insensitive() {
        let params = parse_xclient("ADDR=[unavailable] NAME=[Tempunavail]").unwrap();
        assert_eq!(params.addr, None);
        assert_eq!(params.name, None);
    }

    #[test]
    fn keys_case_insensitive() {
        let params = parse_xclient("addr=1.2.3.4 Name=host.example.com").unwrap();
        assert_eq!(params.addr, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(params.name.as_deref(), Some("host.example.com"));
    }

    #[test]
    fn bad_ip_rejected() {
        assert!(parse_xclient("ADDR=not_an_ip").is_err());
    }

    #[test]
    fn bad_port_rejected() {
        assert!(parse_xclient("PORT=99999").is_err());
    }

    #[test]
    fn empty_args_rejected() {
        assert!(parse_xclient("").is_err());
    }

    #[test]
    fn missing_equals_rejected() {
        assert!(parse_xclient("ADDR").is_err());
    }

    #[test]
    fn unknown_attributes_ignored() {
        let params = parse_xclient("ADDR=1.2.3.4 PROTO=SMTP").unwrap();
        assert_eq!(params.addr, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn name_and_helo_without_addr() {
        let params = parse_xclient("NAME=proxy.example.com HELO=proxy.example.com").unwrap();
        assert_eq!(params.addr, None);
        assert_eq!(params.name.as_deref(), Some("proxy.example.com"));
        assert_eq!(params.helo.as_deref(), Some("proxy.example.com"));
    }
}
