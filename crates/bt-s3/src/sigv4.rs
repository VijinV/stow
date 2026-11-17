//! AWS Signature Version 4 (header-based authorization).
use bt_tls::crypto::hmac::hmac_sha256;
use bt_tls::crypto::sha256::sha256;
use bt_tls::crypto::util::hex;

pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Clone, Copy, Debug)]
pub struct Credentials<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub session_token: Option<&'a str>,
}

/// URI-encode per AWS rules: unreserved characters (A-Z a-z 0-9 - _ . ~) are kept,
/// everything else is %XX (upper-case hex) of its UTF-8 bytes. '/' is kept when
/// `keep_slash` (object key paths).
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    let mut o = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        let keep = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') || (keep_slash && b == b'/');
        if keep {
            o.push(b as char);
        } else {
            o.push('%');
            o.push(H[(b >> 4) as usize] as char);
            o.push(H[(b & 15) as usize] as char);
        }
    }
    o
}

/// Canonical query string from raw (un-encoded) parameters.
pub fn canonical_query(params: &[(String, String)]) -> String {
    let mut enc: Vec<(String, String)> =
        params.iter().map(|(k, v)| (uri_encode(k, false), uri_encode(v, false))).collect();
    enc.sort();
    enc.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&")
}

fn canonical_header_value(v: &str) -> String {
    let mut o = String::with_capacity(v.len());
    let mut space = false;
    for c in v.trim().chars() {
        if c == ' ' || c == '\t' {
            space = true;
        } else {
            if space && !o.is_empty() {
                o.push(' ');
            }
            space = false;
            o.push(c);
        }
    }
    o
}

/// Returns (canonical headers block, signed headers list).
pub fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut hs: Vec<(String, String)> =
        headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), canonical_header_value(v))).collect();
    hs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut merged: Vec<(String, String)> = Vec::new();
    for (k, v) in hs {
        match merged.last_mut() {
            Some(last) if last.0 == k => {
                last.1.push(',');
                last.1.push_str(&v);
            }
            _ => merged.push((k, v)),
        }
    }
    let block: String = merged.iter().map(|(k, v)| format!("{}:{}\n", k, v)).collect();
    let signed = merged.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    (block, signed)
}

pub fn canonical_request(
    method: &str,
    canonical_uri: &str,
    query: &[(String, String)],
    headers: &[(String, String)],
    payload_hash: &str,
) -> (String, String) {
    let (block, signed) = canonical_headers(headers);
    let cr = format!("{}\n{}\n{}\n{}\n{}\n{}", method, canonical_uri, canonical_query(query), block, signed, payload_hash);
    (cr, signed)
}

pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

/// Sign a request in place: adds `x-amz-date` (if absent), `x-amz-security-token`
/// (if a session token is given) and `Authorization`. Every header present in
/// `headers` (which must include `host`) is signed. Returns the signature (hex).
#[allow(clippy::too_many_arguments)]
pub fn sign(
    method: &str,
    canonical_uri: &str,
    query: &[(String, String)],
    headers: &mut Vec<(String, String)>,
    payload_hash: &str,
    creds: &Credentials,
    region: &str,
    service: &str,
    amz_date: &str,
) -> String {
    if !has_header(headers, "x-amz-date") {
        headers.push(("x-amz-date".into(), amz_date.into()));
    }
    if let Some(t) = creds.session_token {
        if !t.is_empty() && !has_header(headers, "x-amz-security-token") {
            headers.push(("x-amz-security-token".into(), t.into()));
        }
    }
    let (cr, signed) = canonical_request(method, canonical_uri, query, headers, payload_hash);
    let date = &amz_date[..8];
    let scope = format!("{}/{}/{}/aws4_request", date, region, service);
    let sts = format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", amz_date, scope, hex(&sha256(cr.as_bytes())));
    let sig = hex(&hmac_sha256(&signing_key(creds.secret_key, date, region, service), sts.as_bytes()));
    headers.push((
        "Authorization".into(),
        format!("AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}", creds.access_key, scope, signed, sig),
    ));
    sig
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    const SUITE: Credentials = Credentials {
        access_key: "AKIDEXAMPLE",
        secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        session_token: None,
    };
    const S3DOC: Credentials = Credentials {
        access_key: "AKIAIOSFODNN7EXAMPLE",
        secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token: None,
    };

    #[test]
    fn suite_get_vanilla() {
        let mut hs = h(&[("Host", "example.amazonaws.com"), ("X-Amz-Date", "20150830T123600Z")]);
        let sig = sign("GET", "/", &[], &mut hs, EMPTY_SHA256, &SUITE, "us-east-1", "service", "20150830T123600Z");
        assert_eq!(sig, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
        let auth = &hs.last().unwrap().1;
        assert_eq!(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    }

    #[test]
    fn suite_query_order() {
        let mut hs = h(&[("Host", "example.amazonaws.com"), ("X-Amz-Date", "20150830T123600Z")]);
        let q = h(&[("Param2", "value2"), ("Param1", "value1")]);
        let sig = sign("GET", "/", &q, &mut hs, EMPTY_SHA256, &SUITE, "us-east-1", "service", "20150830T123600Z");
        assert_eq!(sig, "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500");
    }

    #[test]
    fn suite_post_vanilla() {
        let mut hs = h(&[("Host", "example.amazonaws.com"), ("X-Amz-Date", "20150830T123600Z")]);
        let sig = sign("POST", "/", &[], &mut hs, EMPTY_SHA256, &SUITE, "us-east-1", "service", "20150830T123600Z");
        assert_eq!(sig, "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b");
    }

    #[test]
    fn s3_get_object_range() {
        let mut hs = h(&[
            ("Host", "examplebucket.s3.amazonaws.com"),
            ("Range", "bytes=0-9"),
            ("x-amz-content-sha256", EMPTY_SHA256),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let sig = sign("GET", "/test.txt", &[], &mut hs, EMPTY_SHA256, &S3DOC, "us-east-1", "s3", "20130524T000000Z");
        assert_eq!(sig, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
    }

    #[test]
    fn s3_put_object() {
        let ph = "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072";
        assert_eq!(hex(&sha256(b"Welcome to Amazon S3.")), ph);
        let mut hs = h(&[
            ("Host", "examplebucket.s3.amazonaws.com"),
            ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
            ("x-amz-date", "20130524T000000Z"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ("x-amz-content-sha256", ph),
        ]);
        let uri = format!("/{}", uri_encode("test$file.text", true));
        assert_eq!(uri, "/test%24file.text");
        let sig = sign("PUT", &uri, &[], &mut hs, ph, &S3DOC, "us-east-1", "s3", "20130524T000000Z");
        assert_eq!(sig, "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd");
    }

    #[test]
    fn s3_get_lifecycle_and_list() {
        let base = || {
            h(&[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-date", "20130524T000000Z"),
                ("x-amz-content-sha256", EMPTY_SHA256),
            ])
        };
        let mut hs = base();
        let sig = sign("GET", "/", &h(&[("lifecycle", "")]), &mut hs, EMPTY_SHA256, &S3DOC, "us-east-1", "s3", "20130524T000000Z");
        assert_eq!(sig, "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543");
        let mut hs = base();
        let q = h(&[("max-keys", "2"), ("prefix", "J")]);
        let sig = sign("GET", "/", &q, &mut hs, EMPTY_SHA256, &S3DOC, "us-east-1", "s3", "20130524T000000Z");
        assert_eq!(sig, "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7");
    }

    #[test]
    fn encoding() {
        assert_eq!(uri_encode("a b+c/d~é", true), "a%20b%2Bc/d~%C3%A9");
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
        assert_eq!(canonical_query(&h(&[("b", "2"), ("a", "x y"), ("a", "1")])), "a=1&a=x%20y&b=2");
        let (block, signed) = canonical_headers(&h(&[("My-Header", "  a   b  c "), ("my-header", "d"), ("Host", "h")]));
        assert_eq!(block, "host:h\nmy-header:a b c,d\n");
        assert_eq!(signed, "host;my-header");
    }
}
