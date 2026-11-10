//! OpenVPN management-interface protocol (line based): parsing of server lines and
//! building of the credential commands. Pure code, no I/O.
//!
//! Reference: <https://openvpn.net/community-resources/management-interface/>

/// Prompt sent (without a trailing newline) when the interface is password protected.
pub const PASSWORD_PROMPT: &str = "ENTER PASSWORD:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A `>`-prefixed asynchronous notification.
    Notification(Notification),
    /// `SUCCESS: ...` reply to a command.
    Success(String),
    /// `ERROR: ...` reply to a command.
    Error(String),
    /// Anything else (multi-line command output, `END`, empty lines).
    Data(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    /// `>PASSWORD:Need 'Auth' username/password [SC:<flags>,<text>]`
    NeedAuth {
        static_challenge: Option<StaticChallenge>,
    },
    /// `>PASSWORD:Need 'Private Key' password`
    NeedPrivateKeyPassword,
    /// `>PASSWORD:Verification Failed: 'Auth' [...]`
    AuthFailed { detail: Option<String> },
    /// `>PASSWORD:Auth-Token:<token>`. The token itself is dropped on purpose.
    AuthToken,
    /// `>STATE:<time>,<name>,<desc>,<local ip>,<remote ip>,...`
    State {
        name: String,
        desc: String,
        local_ip: Option<String>,
        remote_ip: Option<String>,
    },
    /// `>BYTECOUNT:<in>,<out>`
    ByteCount { bytes_in: u64, bytes_out: u64 },
    /// `>FATAL:<msg>`
    Fatal(String),
    /// `>HOLD:<msg>`
    Hold(String),
    /// `>INFO:<msg>`
    Info(String),
    /// `>LOG:<time>,<flags>,<msg>`
    Log(String),
    /// Any other notification, raw text after `>`.
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticChallenge {
    pub echo: bool,
    pub text: String,
}

/// Parses one line received from the management interface (without the line terminator).
pub fn parse_line(line: &str) -> Line {
    let line = line.trim_end_matches(['\r', '\n']);
    let line = line.strip_prefix(PASSWORD_PROMPT).unwrap_or(line);
    if let Some(rest) = line.strip_prefix("SUCCESS:") {
        return Line::Success(rest.trim().to_string());
    }
    if let Some(rest) = line.strip_prefix("ERROR:") {
        return Line::Error(rest.trim().to_string());
    }
    match line.strip_prefix('>') {
        Some(rest) => Line::Notification(parse_notification(rest)),
        None => Line::Data(line.to_string()),
    }
}

fn parse_notification(rest: &str) -> Notification {
    let Some((kind, body)) = rest.split_once(':') else {
        return Notification::Other(rest.to_string());
    };
    match kind {
        "PASSWORD" => parse_password(body),
        "STATE" => parse_state(body).unwrap_or_else(|| Notification::Other(rest.to_string())),
        "BYTECOUNT" => {
            let mut it = body.split(',').map(|s| s.trim().parse::<u64>());
            match (it.next(), it.next()) {
                (Some(Ok(bytes_in)), Some(Ok(bytes_out))) => Notification::ByteCount {
                    bytes_in,
                    bytes_out,
                },
                _ => Notification::Other(rest.to_string()),
            }
        }
        "FATAL" => Notification::Fatal(body.to_string()),
        "HOLD" => Notification::Hold(body.to_string()),
        "INFO" => Notification::Info(body.to_string()),
        "LOG" => Notification::Log(body.splitn(3, ',').nth(2).unwrap_or(body).to_string()),
        _ => Notification::Other(rest.to_string()),
    }
}

fn parse_password(body: &str) -> Notification {
    if body.starts_with("Auth-Token:") {
        return Notification::AuthToken;
    }
    if let Some(rest) = body.strip_prefix("Verification Failed: 'Auth'") {
        let detail = rest.trim();
        return Notification::AuthFailed {
            detail: (!detail.is_empty()).then(|| detail.to_string()),
        };
    }
    if let Some(rest) = body.strip_prefix("Need 'Auth' username/password") {
        let static_challenge = rest.trim().strip_prefix("SC:").and_then(|sc| {
            let (flags, text) = sc.split_once(',')?;
            let flags: u32 = flags.trim().parse().ok()?;
            Some(StaticChallenge {
                echo: flags & 1 == 1,
                text: text.to_string(),
            })
        });
        return Notification::NeedAuth { static_challenge };
    }
    if body.starts_with("Need 'Private Key' password") {
        return Notification::NeedPrivateKeyPassword;
    }
    Notification::Other(format!("PASSWORD:{body}"))
}

fn parse_state(body: &str) -> Option<Notification> {
    let f: Vec<&str> = body.split(',').collect();
    let opt = |i: usize| f.get(i).filter(|s| !s.is_empty()).map(|s| s.to_string());
    Some(Notification::State {
        name: f.get(1)?.to_string(),
        desc: f.get(2).unwrap_or(&"").to_string(),
        local_ip: opt(3),
        remote_ip: opt(4),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidValue;

impl std::fmt::Display for InvalidValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "value contains a line break or NUL, which the management protocol cannot carry",
        )
    }
}

impl std::error::Error for InvalidValue {}

/// Quotes a value for a management command: wraps in `"` and escapes `\` and `"`.
pub fn quote(value: &str) -> Result<String, InvalidValue> {
    if value.contains(['\n', '\r', '\0']) {
        return Err(InvalidValue);
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Ok(out)
}

/// `username "Auth" "<user>"`
pub fn username_cmd(user: &str) -> Result<String, InvalidValue> {
    Ok(format!("username \"Auth\" {}", quote(user)?))
}

/// `password "Auth" "<password>"`. Never log the result, use [`redacted`] instead.
pub fn password_cmd(password: &str) -> Result<String, InvalidValue> {
    Ok(format!("password \"Auth\" {}", quote(password)?))
}

/// Static-challenge response format: `SCRV1:<base64 password>:<base64 response>`.
pub fn static_challenge_response(password: &str, response: &str) -> String {
    format!(
        "SCRV1:{}:{}",
        base64(password.as_bytes()),
        base64(response.as_bytes())
    )
}

/// Log-safe form of a command: keeps the verb and realm, hides the value.
pub fn redacted(cmd: &str) -> String {
    match cmd.split_once(" \"Auth\" ") {
        Some((verb, _)) if verb == "password" => "password \"Auth\" ********".to_string(),
        _ => cmd.to_string(),
    }
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notif(s: &str) -> Notification {
        match parse_line(s) {
            Line::Notification(n) => n,
            other => panic!("not a notification: {other:?}"),
        }
    }

    #[test]
    fn need_auth() {
        assert_eq!(
            notif(">PASSWORD:Need 'Auth' username/password"),
            Notification::NeedAuth {
                static_challenge: None
            }
        );
        assert_eq!(
            notif(">PASSWORD:Need 'Auth' username/password SC:1,Enter OTP"),
            Notification::NeedAuth {
                static_challenge: Some(StaticChallenge {
                    echo: true,
                    text: "Enter OTP".into()
                })
            }
        );
    }

    #[test]
    fn auth_failed_and_token() {
        assert_eq!(
            notif(">PASSWORD:Verification Failed: 'Auth'"),
            Notification::AuthFailed { detail: None }
        );
        assert_eq!(
            notif(">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:abc:dXNlcg==:Enter code']"),
            Notification::AuthFailed {
                detail: Some("['CRV1:R,E:abc:dXNlcg==:Enter code']".into())
            }
        );
        assert_eq!(
            notif(">PASSWORD:Auth-Token:secret123"),
            Notification::AuthToken
        );
        assert_eq!(
            notif(">PASSWORD:Need 'Private Key' password"),
            Notification::NeedPrivateKeyPassword
        );
    }

    #[test]
    fn state_bytecount_fatal() {
        assert_eq!(
            notif(">STATE:1700000000,CONNECTED,SUCCESS,10.81.234.6,203.0.113.10,8443,,"),
            Notification::State {
                name: "CONNECTED".into(),
                desc: "SUCCESS".into(),
                local_ip: Some("10.81.234.6".into()),
                remote_ip: Some("203.0.113.10".into()),
            }
        );
        assert_eq!(
            notif(">STATE:1700000000,RECONNECTING,tls-error,,,,,"),
            Notification::State {
                name: "RECONNECTING".into(),
                desc: "tls-error".into(),
                local_ip: None,
                remote_ip: None,
            }
        );
        assert_eq!(
            notif(">BYTECOUNT:1234,5678"),
            Notification::ByteCount {
                bytes_in: 1234,
                bytes_out: 5678
            }
        );
        assert_eq!(
            notif(">FATAL:cannot allocate TUN"),
            Notification::Fatal("cannot allocate TUN".into())
        );
        assert_eq!(
            notif(">HOLD:Waiting for hold release:0"),
            Notification::Hold("Waiting for hold release:0".into())
        );
        assert_eq!(
            notif(">LOG:1700000000,I,Initialization Sequence Completed"),
            Notification::Log("Initialization Sequence Completed".into())
        );
    }

    #[test]
    fn malformed() {
        assert_eq!(
            notif(">BYTECOUNT:abc,1"),
            Notification::Other("BYTECOUNT:abc,1".into())
        );
        assert_eq!(notif(">STATE:"), Notification::Other("STATE:".into()));
        assert_eq!(notif(">garbage"), Notification::Other("garbage".into()));
        assert_eq!(parse_line(""), Line::Data(String::new()));
        assert_eq!(parse_line("END"), Line::Data("END".into()));
    }

    #[test]
    fn replies_and_password_prompt() {
        assert_eq!(
            parse_line("ENTER PASSWORD:SUCCESS: password is correct\r"),
            Line::Success("password is correct".into())
        );
        assert_eq!(
            parse_line("ERROR: unknown command"),
            Line::Error("unknown command".into())
        );
        assert_eq!(
            parse_line("ENTER PASSWORD:>INFO:OpenVPN Management Interface Version 5"),
            Line::Notification(Notification::Info(
                "OpenVPN Management Interface Version 5".into()
            ))
        );
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("plain").unwrap(), r#""plain""#);
        assert_eq!(quote(r#"a"b\c"#).unwrap(), r#""a\"b\\c""#);
        assert_eq!(quote("pässwörd 🔑").unwrap(), "\"pässwörd 🔑\"");
        assert_eq!(quote("a\nb"), Err(InvalidValue));
        assert_eq!(
            password_cmd("p\"w123456").unwrap(),
            r#"password "Auth" "p\"w123456""#
        );
        assert_eq!(username_cmd("soham").unwrap(), r#"username "Auth" "soham""#);
    }

    #[test]
    fn redaction() {
        assert_eq!(
            redacted(&password_cmd("hunter2").unwrap()),
            "password \"Auth\" ********"
        );
        assert_eq!(
            redacted(&username_cmd("u").unwrap()),
            "username \"Auth\" \"u\""
        );
        assert_eq!(redacted("hold release"), "hold release");
    }

    #[test]
    fn base64_vectors() {
        // RFC 4648 section 10.
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(i.as_bytes()), o);
        }
        assert_eq!(
            static_challenge_response("pw", "123456"),
            "SCRV1:cHc=:MTIzNDU2"
        );
    }
}
