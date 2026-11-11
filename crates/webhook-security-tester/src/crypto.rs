use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

fn mac(secret: &[u8], bytes: &[u8]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(bytes);
    mac
}
pub fn github_sign(secret: &[u8], body: &[u8]) -> String {
    format!(
        "sha256={}",
        hex::encode(mac(secret, body).finalize().into_bytes())
    )
}
pub fn github_verify(secret: &[u8], body: &[u8], value: &str) -> bool {
    let Some(digest) = value.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(bytes) = hex::decode(digest) else {
        return false;
    };
    mac(secret, body).verify_slice(&bytes).is_ok()
}
pub fn timestamp_sign(secret: &[u8], body: &[u8], timestamp: i64) -> String {
    let mut bytes = format!("{timestamp}.").into_bytes();
    bytes.extend_from_slice(body);
    format!(
        "t={timestamp},v1={}",
        hex::encode(mac(secret, &bytes).finalize().into_bytes())
    )
}
pub fn timestamp_verify(
    secret: &[u8],
    body: &[u8],
    value: &str,
    now: i64,
    tolerance: i64,
    future_skew: i64,
) -> bool {
    let mut parts = value.split(',');
    let (Some(t), Some(v), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let (Some(t), Some(v)) = (t.strip_prefix("t="), v.strip_prefix("v1=")) else {
        return false;
    };
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(timestamp) = t.parse::<i64>() else {
        return false;
    };
    let Some(age) = now.checked_sub(timestamp) else {
        return false;
    };
    if age > tolerance || age < -future_skew {
        return false;
    }
    let Ok(bytes) = hex::decode(v) else {
        return false;
    };
    let mut signed = format!("{timestamp}.").into_bytes();
    signed.extend_from_slice(body);
    mac(secret, &signed).verify_slice(&bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn github_vector() {
        assert_eq!(
            github_sign(b"It's a Secret to Everybody", b"Hello, World!"),
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
        );
    }
    #[test]
    fn malformed_rejected() {
        for s in ["", "sha1=abcd", "sha256=gg", "sha256=00"] {
            assert!(!github_verify(b"s", b"body", s));
        }
    }
    #[test]
    fn timestamp_boundaries() {
        let s = timestamp_sign(b"s", b"body", 700);
        assert!(timestamp_verify(b"s", b"body", &s, 1000, 300, 30));
        assert!(!timestamp_verify(b"s", b"body", &s, 1001, 300, 30));
        let future = timestamp_sign(b"s", b"body", 1031);
        assert!(!timestamp_verify(b"s", b"body", &future, 1000, 300, 30));
    }
    #[test]
    fn timestamp_parser_rejects_missing_malformed_and_wrong_mac() {
        let secret = b"test-secret";
        let body = b"raw body";
        let signed = timestamp_sign(secret, body, 1000);
        assert!(timestamp_verify(secret, body, &signed, 1000, 300, 30));
        for value in [
            "v1=abcd",
            "t=oops,v1=abcd",
            "t=1000,v1=gg",
            "t=1000,v1=00",
            "t=1000,v1=00,extra=1",
        ] {
            assert!(!timestamp_verify(secret, body, value, 1000, 300, 30));
        }
        assert!(!timestamp_verify(
            b"other-secret",
            body,
            &signed,
            1000,
            300,
            30
        ));
    }
}
