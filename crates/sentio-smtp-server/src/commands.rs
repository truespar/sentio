use crate::response::SmtpResponse;
use crate::xclient::{self, XClientParams};

/// ESMTP body encoding type from BODY= parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyType {
    SevenBit,
    EightBitMime,
}

/// DSN RET parameter (RFC 3461 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsnRet {
    Full,
    Hdrs,
}

/// DSN NOTIFY conditions (RFC 3461 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsnNotify {
    Never,
    /// Combination of Success, Failure, Delay flags.
    Flags {
        success: bool,
        failure: bool,
        delay: bool,
    },
}

/// Parameters parsed from MAIL FROM command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailFromParams {
    pub path: String,
    pub size: Option<u64>,
    pub body: Option<BodyType>,
    pub smtputf8: bool,
    /// DSN RET parameter (RFC 3461).
    pub ret: Option<DsnRet>,
    /// DSN ENVID parameter (RFC 3461).
    pub envid: Option<String>,
    /// AUTH= parameter (RFC 4954 §4): authenticated sender identity.
    pub auth_param: Option<String>,
}

/// Parameters parsed from RCPT TO command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcptToParams {
    pub path: String,
    /// DSN NOTIFY parameter (RFC 3461).
    pub notify: Option<DsnNotify>,
    /// DSN ORCPT parameter (RFC 3461).
    pub orcpt: Option<String>,
}

/// Parsed SMTP command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpCommand {
    Ehlo(String),
    Helo(String),
    MailFrom(MailFromParams),
    RcptTo(RcptToParams),
    Data,
    Quit,
    Rset,
    Noop,
    Vrfy(String),
    Help,
    StartTls,
    Auth(String),
    /// BDAT chunked transfer (RFC 3030).
    Bdat {
        size: u64,
        last: bool,
    },
    /// XCLIENT proxy metadata (Postfix extension).
    XClient(XClientParams),
    /// Recognized but not implemented commands (EXPN, TURN, ETRN).
    NotImplemented(String),
    Unknown(String),
}

/// Parse a single SMTP command line (without trailing CRLF).
pub fn parse(line: &[u8]) -> Result<SmtpCommand, SmtpResponse> {
    let text = std::str::from_utf8(line).map_err(|_| SmtpResponse::syntax_error())?;
    let trimmed = text.trim_end();

    if trimmed.is_empty() {
        return Err(SmtpResponse::command_not_recognized());
    }

    // Split on first space to get verb and rest
    let (verb, rest) = match trimmed.find(' ') {
        Some(pos) => (&trimmed[..pos], trimmed[pos + 1..].trim()),
        None => (trimmed, ""),
    };

    let verb_upper = verb.to_ascii_uppercase();

    match verb_upper.as_str() {
        "EHLO" => {
            if rest.is_empty() {
                return Err(SmtpResponse::syntax_error());
            }
            Ok(SmtpCommand::Ehlo(rest.to_string()))
        }
        "HELO" => {
            if rest.is_empty() {
                return Err(SmtpResponse::syntax_error());
            }
            Ok(SmtpCommand::Helo(rest.to_string()))
        }
        "MAIL" => parse_mail_from(rest),
        "RCPT" => parse_rcpt_to(rest),
        "DATA" => {
            if !rest.is_empty() {
                return Err(SmtpResponse::syntax_error());
            }
            Ok(SmtpCommand::Data)
        }
        "QUIT" => Ok(SmtpCommand::Quit),
        "RSET" => Ok(SmtpCommand::Rset),
        "NOOP" => Ok(SmtpCommand::Noop),
        "VRFY" => Ok(SmtpCommand::Vrfy(rest.to_string())),
        "HELP" => Ok(SmtpCommand::Help),
        "STARTTLS" => {
            if !rest.is_empty() {
                return Err(SmtpResponse::syntax_error());
            }
            Ok(SmtpCommand::StartTls)
        }
        "AUTH" => {
            if rest.is_empty() {
                return Err(SmtpResponse::syntax_error());
            }
            Ok(SmtpCommand::Auth(rest.to_string()))
        }
        "BDAT" => parse_bdat(rest),
        "XCLIENT" => xclient::parse_xclient(rest).map(SmtpCommand::XClient),
        "EXPN" | "TURN" | "ETRN" => Ok(SmtpCommand::NotImplemented(verb_upper)),
        _ => Ok(SmtpCommand::Unknown(verb_upper)),
    }
}

/// Parse `FROM:<path> [params...]`
fn parse_mail_from(rest: &str) -> Result<SmtpCommand, SmtpResponse> {
    // Expect "FROM:" prefix (case-insensitive)
    let rest_upper = rest.to_ascii_uppercase();
    if !rest_upper.starts_with("FROM:") {
        return Err(SmtpResponse::syntax_error());
    }
    let after_from = rest[5..].trim_start();

    let (path, params_str) = extract_angle_path(after_from)?;

    let mut size = None;
    let mut body = None;
    let mut smtputf8 = false;
    let mut ret = None;
    let mut envid = None;
    let mut auth_param = None;

    for param in params_str.split_whitespace() {
        let param_upper = param.to_ascii_uppercase();
        if let Some(val) = param_upper.strip_prefix("SIZE=") {
            size = Some(
                val.parse::<u64>()
                    .map_err(|_| SmtpResponse::syntax_error())?,
            );
        } else if let Some(val) = param_upper.strip_prefix("BODY=") {
            body = Some(match val {
                "7BIT" => BodyType::SevenBit,
                "8BITMIME" => BodyType::EightBitMime,
                _ => return Err(SmtpResponse::syntax_error()),
            });
        } else if param_upper == "SMTPUTF8" {
            smtputf8 = true;
        } else if let Some(val) = param_upper.strip_prefix("RET=") {
            ret = Some(match val {
                "FULL" => DsnRet::Full,
                "HDRS" => DsnRet::Hdrs,
                _ => return Err(SmtpResponse::syntax_error()),
            });
        } else if let Some(val) = param
            .strip_prefix("ENVID=")
            .or_else(|| param.strip_prefix("envid="))
        {
            // ENVID value is case-sensitive (xtext-encoded), use original case
            if val.is_empty() {
                return Err(SmtpResponse::syntax_error());
            }
            envid = Some(val.to_string());
        } else if let Some(val) = param
            .strip_prefix("AUTH=")
            .or_else(|| param.strip_prefix("auth="))
        {
            // RFC 4954 §4: AUTH= parameter carries the authenticated sender identity.
            // "<>" means the identity is unknown/empty.
            if val == "<>" {
                auth_param = Some(String::new());
            } else {
                auth_param = Some(val.to_string());
            }
        }
        // Unknown params are silently ignored per RFC 5321
    }

    Ok(SmtpCommand::MailFrom(MailFromParams {
        path,
        size,
        body,
        smtputf8,
        ret,
        envid,
        auth_param,
    }))
}

/// Parse `TO:<path> [params...]`
fn parse_rcpt_to(rest: &str) -> Result<SmtpCommand, SmtpResponse> {
    let rest_upper = rest.to_ascii_uppercase();
    if !rest_upper.starts_with("TO:") {
        return Err(SmtpResponse::syntax_error());
    }
    let after_to = rest[3..].trim_start();

    let (path, params_str) = extract_angle_path(after_to)?;

    if path.is_empty() {
        // Empty RCPT TO:<> is not valid (unlike MAIL FROM)
        return Err(SmtpResponse::syntax_error());
    }

    let mut notify = None;
    let mut orcpt = None;

    for param in params_str.split_whitespace() {
        let param_upper = param.to_ascii_uppercase();
        if let Some(val) = param_upper.strip_prefix("NOTIFY=") {
            notify = Some(parse_dsn_notify(val)?);
        } else if let Some(val) = param
            .strip_prefix("ORCPT=")
            .or_else(|| param.strip_prefix("orcpt="))
        {
            // ORCPT value is case-sensitive (addr-type;addr), use original case
            if val.is_empty() || !val.contains(';') {
                return Err(SmtpResponse::syntax_error());
            }
            orcpt = Some(val.to_string());
        }
        // Unknown params are silently ignored per RFC 5321
    }

    Ok(SmtpCommand::RcptTo(RcptToParams {
        path,
        notify,
        orcpt,
    }))
}

/// Parse `BDAT <size> [LAST]` (RFC 3030).
fn parse_bdat(rest: &str) -> Result<SmtpCommand, SmtpResponse> {
    if rest.is_empty() {
        return Err(SmtpResponse::syntax_error());
    }
    let mut parts = rest.split_whitespace();
    let size_str = parts.next().ok_or_else(SmtpResponse::syntax_error)?;
    let size = size_str
        .parse::<u64>()
        .map_err(|_| SmtpResponse::syntax_error())?;
    let last = parts
        .next()
        .map(|s| s.eq_ignore_ascii_case("LAST"))
        .unwrap_or(false);
    Ok(SmtpCommand::Bdat { size, last })
}

/// Parse NOTIFY= value: NEVER, or comma-separated list of SUCCESS, FAILURE, DELAY.
fn parse_dsn_notify(val: &str) -> Result<DsnNotify, SmtpResponse> {
    if val == "NEVER" {
        return Ok(DsnNotify::Never);
    }

    let mut success = false;
    let mut failure = false;
    let mut delay = false;

    for token in val.split(',') {
        match token {
            "SUCCESS" => success = true,
            "FAILURE" => failure = true,
            "DELAY" => delay = true,
            _ => return Err(SmtpResponse::syntax_error()),
        }
    }

    // Must have at least one flag
    if !success && !failure && !delay {
        return Err(SmtpResponse::syntax_error());
    }

    Ok(DsnNotify::Flags {
        success,
        failure,
        delay,
    })
}

/// Extract an address from angle brackets. Returns (address, remaining_params_str).
/// Supports `<addr>` and bare `addr` (lenient), plus empty `<>` for bounce path.
/// Source routes (`@relay:user@domain`) are accepted and stripped per RFC 5321 §4.1.1.3.
fn extract_angle_path(s: &str) -> Result<(String, &str), SmtpResponse> {
    if let Some(start) = s.find('<') {
        let end = s.find('>').ok_or_else(SmtpResponse::syntax_error)?;
        if end < start {
            return Err(SmtpResponse::syntax_error());
        }
        let mut addr = s[start + 1..end].trim().to_string();
        // RFC 5321 §4.1.1.3: strip source routes (@relay1,@relay2:user@domain → user@domain)
        if addr.starts_with('@') {
            if let Some(colon_pos) = addr.find(':') {
                addr = addr[colon_pos + 1..].trim().to_string();
            }
        }
        let rest = s[end + 1..].trim();
        Ok((addr, rest))
    } else {
        // No angle brackets - take the first token as the address
        let (addr, rest) = match s.find(' ') {
            Some(pos) => (s[..pos].to_string(), s[pos + 1..].trim()),
            None => (s.to_string(), ""),
        };
        Ok((addr, rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ehlo() {
        let cmd = parse(b"EHLO example.com").unwrap();
        assert_eq!(cmd, SmtpCommand::Ehlo("example.com".into()));
    }

    #[test]
    fn parse_ehlo_case_insensitive() {
        let cmd = parse(b"ehlo EXAMPLE.COM").unwrap();
        assert_eq!(cmd, SmtpCommand::Ehlo("EXAMPLE.COM".into()));
    }

    #[test]
    fn parse_ehlo_no_domain() {
        assert!(parse(b"EHLO").is_err());
    }

    #[test]
    fn parse_helo() {
        let cmd = parse(b"HELO example.com").unwrap();
        assert_eq!(cmd, SmtpCommand::Helo("example.com".into()));
    }

    #[test]
    fn parse_mail_from_basic() {
        let cmd = parse(b"MAIL FROM:<user@example.com>").unwrap();
        assert_eq!(
            cmd,
            SmtpCommand::MailFrom(MailFromParams {
                path: "user@example.com".into(),
                size: None,
                body: None,
                smtputf8: false,
                ret: None,
                envid: None,
                auth_param: None,
            })
        );
    }

    #[test]
    fn parse_mail_from_empty_bounce_path() {
        let cmd = parse(b"MAIL FROM:<>").unwrap();
        assert_eq!(
            cmd,
            SmtpCommand::MailFrom(MailFromParams {
                path: String::new(),
                size: None,
                body: None,
                smtputf8: false,
                ret: None,
                envid: None,
                auth_param: None,
            })
        );
    }

    #[test]
    fn parse_mail_from_with_size() {
        let cmd = parse(b"MAIL FROM:<user@example.com> SIZE=1024").unwrap();
        match cmd {
            SmtpCommand::MailFrom(p) => {
                assert_eq!(p.path, "user@example.com");
                assert_eq!(p.size, Some(1024));
            }
            _ => panic!("expected MailFrom"),
        }
    }

    #[test]
    fn parse_mail_from_with_body_and_smtputf8() {
        let cmd = parse(b"MAIL FROM:<u@ex.com> BODY=8BITMIME SMTPUTF8").unwrap();
        match cmd {
            SmtpCommand::MailFrom(p) => {
                assert_eq!(p.body, Some(BodyType::EightBitMime));
                assert!(p.smtputf8);
            }
            _ => panic!("expected MailFrom"),
        }
    }

    #[test]
    fn parse_mail_from_case_insensitive() {
        let cmd = parse(b"mail from:<a@b.com>").unwrap();
        assert!(matches!(cmd, SmtpCommand::MailFrom(_)));
    }

    #[test]
    fn parse_rcpt_to() {
        let cmd = parse(b"RCPT TO:<user@example.com>").unwrap();
        assert_eq!(
            cmd,
            SmtpCommand::RcptTo(RcptToParams {
                path: "user@example.com".into(),
                notify: None,
                orcpt: None,
            })
        );
    }

    #[test]
    fn parse_rcpt_to_empty_rejected() {
        assert!(parse(b"RCPT TO:<>").is_err());
    }

    #[test]
    fn parse_data() {
        assert_eq!(parse(b"DATA").unwrap(), SmtpCommand::Data);
    }

    #[test]
    fn parse_data_with_args_rejected() {
        assert!(parse(b"DATA extra").is_err());
    }

    #[test]
    fn parse_quit() {
        assert_eq!(parse(b"QUIT").unwrap(), SmtpCommand::Quit);
    }

    #[test]
    fn parse_rset() {
        assert_eq!(parse(b"RSET").unwrap(), SmtpCommand::Rset);
    }

    #[test]
    fn parse_noop() {
        assert_eq!(parse(b"NOOP").unwrap(), SmtpCommand::Noop);
    }

    #[test]
    fn parse_vrfy() {
        assert_eq!(
            parse(b"VRFY postmaster").unwrap(),
            SmtpCommand::Vrfy("postmaster".into())
        );
    }

    #[test]
    fn parse_help() {
        assert_eq!(parse(b"HELP").unwrap(), SmtpCommand::Help);
    }

    #[test]
    fn parse_starttls() {
        assert_eq!(parse(b"STARTTLS").unwrap(), SmtpCommand::StartTls);
    }

    #[test]
    fn parse_auth() {
        let cmd = parse(b"AUTH PLAIN dGVzdA==").unwrap();
        assert_eq!(cmd, SmtpCommand::Auth("PLAIN dGVzdA==".into()));
    }

    #[test]
    fn parse_expn_not_implemented() {
        let cmd = parse(b"EXPN list").unwrap();
        assert_eq!(cmd, SmtpCommand::NotImplemented("EXPN".into()));
    }

    #[test]
    fn parse_bdat_size_only() {
        let cmd = parse(b"BDAT 1024").unwrap();
        assert_eq!(
            cmd,
            SmtpCommand::Bdat {
                size: 1024,
                last: false
            }
        );
    }

    #[test]
    fn parse_bdat_with_last() {
        let cmd = parse(b"BDAT 512 LAST").unwrap();
        assert_eq!(
            cmd,
            SmtpCommand::Bdat {
                size: 512,
                last: true
            }
        );
    }

    #[test]
    fn parse_bdat_no_size_rejected() {
        assert!(parse(b"BDAT").is_err());
    }

    #[test]
    fn parse_bdat_bad_size_rejected() {
        assert!(parse(b"BDAT abc").is_err());
    }

    #[test]
    fn parse_turn_not_implemented() {
        let cmd = parse(b"TURN").unwrap();
        assert_eq!(cmd, SmtpCommand::NotImplemented("TURN".into()));
    }

    #[test]
    fn parse_etrn_not_implemented() {
        let cmd = parse(b"ETRN example.com").unwrap();
        assert_eq!(cmd, SmtpCommand::NotImplemented("ETRN".into()));
    }

    #[test]
    fn parse_unknown_command() {
        let cmd = parse(b"XYZZY").unwrap();
        assert_eq!(cmd, SmtpCommand::Unknown("XYZZY".into()));
    }

    #[test]
    fn parse_empty_line_rejected() {
        assert!(parse(b"").is_err());
    }

    #[test]
    fn parse_mail_from_bad_size() {
        assert!(parse(b"MAIL FROM:<a@b.com> SIZE=abc").is_err());
    }

    #[test]
    fn parse_mail_from_bad_body() {
        assert!(parse(b"MAIL FROM:<a@b.com> BODY=BINARY").is_err());
    }

    // ── DSN parameter tests ───────────────────────────────────────────

    #[test]
    fn parse_mail_from_ret_full() {
        let cmd = parse(b"MAIL FROM:<u@ex.com> RET=FULL ENVID=abc123").unwrap();
        match cmd {
            SmtpCommand::MailFrom(p) => {
                assert_eq!(p.ret, Some(DsnRet::Full));
                assert_eq!(p.envid.as_deref(), Some("abc123"));
            }
            _ => panic!("expected MailFrom"),
        }
    }

    #[test]
    fn parse_mail_from_ret_hdrs() {
        let cmd = parse(b"MAIL FROM:<u@ex.com> RET=HDRS").unwrap();
        match cmd {
            SmtpCommand::MailFrom(p) => {
                assert_eq!(p.ret, Some(DsnRet::Hdrs));
                assert_eq!(p.envid, None);
            }
            _ => panic!("expected MailFrom"),
        }
    }

    #[test]
    fn parse_mail_from_invalid_ret() {
        assert!(parse(b"MAIL FROM:<u@ex.com> RET=BODY").is_err());
    }

    #[test]
    fn parse_rcpt_to_notify_success_failure() {
        let cmd = parse(b"RCPT TO:<u@ex.com> NOTIFY=SUCCESS,FAILURE").unwrap();
        match cmd {
            SmtpCommand::RcptTo(p) => {
                assert_eq!(
                    p.notify,
                    Some(DsnNotify::Flags {
                        success: true,
                        failure: true,
                        delay: false,
                    })
                );
            }
            _ => panic!("expected RcptTo"),
        }
    }

    #[test]
    fn parse_rcpt_to_notify_never() {
        let cmd = parse(b"RCPT TO:<u@ex.com> NOTIFY=NEVER").unwrap();
        match cmd {
            SmtpCommand::RcptTo(p) => {
                assert_eq!(p.notify, Some(DsnNotify::Never));
            }
            _ => panic!("expected RcptTo"),
        }
    }

    #[test]
    fn parse_rcpt_to_orcpt() {
        let cmd = parse(b"RCPT TO:<u@ex.com> ORCPT=rfc822;user@example.com").unwrap();
        match cmd {
            SmtpCommand::RcptTo(p) => {
                assert_eq!(p.orcpt.as_deref(), Some("rfc822;user@example.com"));
            }
            _ => panic!("expected RcptTo"),
        }
    }

    #[test]
    fn parse_rcpt_to_invalid_notify() {
        assert!(parse(b"RCPT TO:<u@ex.com> NOTIFY=BOGUS").is_err());
    }

    // ── AUTH= parameter tests (RFC 4954 §4) ─────────────────────────

    #[test]
    fn parse_mail_from_auth_identity() {
        let cmd = parse(b"MAIL FROM:<u@ex.com> AUTH=sender@example.com").unwrap();
        match cmd {
            SmtpCommand::MailFrom(p) => {
                assert_eq!(p.auth_param.as_deref(), Some("sender@example.com"));
            }
            _ => panic!("expected MailFrom"),
        }
    }

    #[test]
    fn parse_mail_from_auth_empty() {
        let cmd = parse(b"MAIL FROM:<u@ex.com> AUTH=<>").unwrap();
        match cmd {
            SmtpCommand::MailFrom(p) => {
                assert_eq!(p.auth_param.as_deref(), Some(""));
            }
            _ => panic!("expected MailFrom"),
        }
    }

    // ── Source route tests (RFC 5321 §4.1.1.3) ────────────────────────

    #[test]
    fn parse_rcpt_to_source_route_stripped() {
        let cmd = parse(b"RCPT TO:<@relay.example.com:user@example.com>").unwrap();
        match cmd {
            SmtpCommand::RcptTo(p) => {
                assert_eq!(p.path, "user@example.com");
            }
            _ => panic!("expected RcptTo"),
        }
    }

    #[test]
    fn parse_rcpt_to_multi_hop_source_route_stripped() {
        let cmd = parse(b"RCPT TO:<@relay1.com,@relay2.com:user@example.com>").unwrap();
        match cmd {
            SmtpCommand::RcptTo(p) => {
                assert_eq!(p.path, "user@example.com");
            }
            _ => panic!("expected RcptTo"),
        }
    }

    #[test]
    fn parse_mail_from_source_route_stripped() {
        let cmd = parse(b"MAIL FROM:<@relay.com:sender@example.com>").unwrap();
        match cmd {
            SmtpCommand::MailFrom(p) => {
                assert_eq!(p.path, "sender@example.com");
            }
            _ => panic!("expected MailFrom"),
        }
    }

    // ── Address literal tests (RFC 5321 §4.1.3) ──────────────────────

    #[test]
    fn parse_rcpt_to_ipv4_literal() {
        let cmd = parse(b"RCPT TO:<user@[192.168.1.1]>").unwrap();
        match cmd {
            SmtpCommand::RcptTo(p) => {
                assert_eq!(p.path, "user@[192.168.1.1]");
            }
            _ => panic!("expected RcptTo"),
        }
    }

    #[test]
    fn parse_rcpt_to_ipv6_literal() {
        let cmd = parse(b"RCPT TO:<user@[IPv6:2001:db8::1]>").unwrap();
        match cmd {
            SmtpCommand::RcptTo(p) => {
                assert_eq!(p.path, "user@[IPv6:2001:db8::1]");
            }
            _ => panic!("expected RcptTo"),
        }
    }

    #[test]
    fn parse_mail_from_ipv4_literal() {
        let cmd = parse(b"MAIL FROM:<sender@[10.0.0.1]>").unwrap();
        match cmd {
            SmtpCommand::MailFrom(p) => {
                assert_eq!(p.path, "sender@[10.0.0.1]");
            }
            _ => panic!("expected MailFrom"),
        }
    }

    #[test]
    fn parse_ehlo_address_literal() {
        let cmd = parse(b"EHLO [127.0.0.1]").unwrap();
        assert_eq!(cmd, SmtpCommand::Ehlo("[127.0.0.1]".into()));
    }

    #[test]
    fn parse_ehlo_ipv6_literal() {
        let cmd = parse(b"EHLO [IPv6:2001:db8::1]").unwrap();
        assert_eq!(cmd, SmtpCommand::Ehlo("[IPv6:2001:db8::1]".into()));
    }

    // ── Bare postmaster test (RFC 5321 §2.3.4) ───────────────────────

    #[test]
    fn parse_rcpt_to_bare_postmaster() {
        let cmd = parse(b"RCPT TO:<postmaster>").unwrap();
        match cmd {
            SmtpCommand::RcptTo(p) => {
                assert_eq!(p.path, "postmaster");
            }
            _ => panic!("expected RcptTo"),
        }
    }
}
