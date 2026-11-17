//! TLS 1.3 client (RFC 8446), written from scratch.
//!
//! Supported: TLS_CHACHA20_POLY1305_SHA256 (preferred), TLS_AES_128_GCM_SHA256,
//! TLS_AES_256_GCM_SHA384; X25519 key exchange (with HelloRetryRequest cookie
//! handling); server signatures RSA-PSS and ECDSA P-256/P-384; full X.509 chain
//! validation against a [`RootStore`]. No session resumption / 0-RTT / client certs.
use crate::crypto::aes_gcm::AesGcm;
use crate::crypto::chacha20poly1305::ChaCha20Poly1305;
use crate::crypto::ecdsa::{self, Curve};
use crate::crypto::hash::HashAlg;
use crate::crypto::hkdf;
use crate::crypto::hmac::hmac;
use crate::crypto::random;
use crate::crypto::util::ct_eq;
use crate::crypto::x25519;
use crate::roots::RootStore;
use crate::x509::{self, PublicKey};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

const CT_CCS: u8 = 20;
const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APP: u8 = 23;

const HT_CLIENT_HELLO: u8 = 1;
const HT_SERVER_HELLO: u8 = 2;
const HT_NEW_SESSION_TICKET: u8 = 4;
const HT_ENCRYPTED_EXTENSIONS: u8 = 8;
const HT_CERTIFICATE: u8 = 11;
const HT_CERTIFICATE_REQUEST: u8 = 13;
const HT_CERTIFICATE_VERIFY: u8 = 15;
const HT_FINISHED: u8 = 20;
const HT_KEY_UPDATE: u8 = 24;
const HT_MESSAGE_HASH: u8 = 254;

const SUITE_AES128: u16 = 0x1301;
const SUITE_AES256: u16 = 0x1302;
const SUITE_CHACHA: u16 = 0x1303;

const GROUP_X25519: u16 = 0x001d;

const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11,
    0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

const SIG_ALGS: &[u16] = &[
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0401, // rsa_pkcs1_sha256 (certificates only)
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
];

const MAX_PLAINTEXT: usize = 16384;

fn tls_err(msg: impl Into<String>) -> io::Error {
    let m = msg.into();
    let m = if m.starts_with("TLS: ") { m } else { format!("TLS: {m}") };
    io::Error::new(io::ErrorKind::InvalidData, m)
}

fn alert_name(code: u8) -> &'static str {
    match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown alert",
    }
}

#[derive(Clone, Copy)]
struct Suite {
    id: u16,
    hash: HashAlg,
    key_len: usize,
}

impl Suite {
    fn from_id(id: u16) -> Option<Suite> {
        match id {
            SUITE_CHACHA => Some(Suite { id, hash: HashAlg::Sha256, key_len: 32 }),
            SUITE_AES128 => Some(Suite { id, hash: HashAlg::Sha256, key_len: 16 }),
            SUITE_AES256 => Some(Suite { id, hash: HashAlg::Sha384, key_len: 32 }),
            _ => None,
        }
    }
    fn name(&self) -> &'static str {
        match self.id {
            SUITE_CHACHA => "TLS_CHACHA20_POLY1305_SHA256",
            SUITE_AES128 => "TLS_AES_128_GCM_SHA256",
            _ => "TLS_AES_256_GCM_SHA384",
        }
    }
}

/// HKDF-Expand-Label (RFC 8446 7.1)
pub fn expand_label(alg: HashAlg, secret: &[u8], label: &str, ctx: &[u8], len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len() + ctx.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(ctx.len() as u8);
    info.extend_from_slice(ctx);
    hkdf::expand(alg, secret, &info, len)
}

pub fn derive_secret(alg: HashAlg, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    expand_label(alg, secret, label, transcript_hash, alg.output_len())
}

enum Aead {
    ChaCha(ChaCha20Poly1305),
    Aes(AesGcm),
}

/// One direction of record protection.
struct Protection {
    aead: Aead,
    iv: [u8; 12],
    seq: u64,
    secret: Vec<u8>,
    suite: Suite,
}

impl Protection {
    fn new(suite: Suite, secret: Vec<u8>) -> Protection {
        let key = expand_label(suite.hash, &secret, "key", &[], suite.key_len);
        let ivv = expand_label(suite.hash, &secret, "iv", &[], 12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&ivv);
        let aead = if suite.id == SUITE_CHACHA {
            let mut k = [0u8; 32];
            k.copy_from_slice(&key);
            Aead::ChaCha(ChaCha20Poly1305::new(&k))
        } else {
            Aead::Aes(AesGcm::new(&key))
        };
        Protection { aead, iv, seq: 0, secret, suite }
    }

    fn update(&mut self) {
        let next = expand_label(self.suite.hash, &self.secret, "traffic upd", &[], self.suite.hash.output_len());
        *self = Protection::new(self.suite, next);
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let s = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        n
    }

    /// Builds a complete encrypted record carrying `data` of inner content type `ct`.
    fn seal(&mut self, ct: u8, data: &[u8], out: &mut Vec<u8>) {
        let inner_len = data.len() + 1;
        let rec_len = inner_len + 16;
        let start = out.len();
        out.extend_from_slice(&[CT_APP, 3, 3, (rec_len >> 8) as u8, rec_len as u8]);
        out.extend_from_slice(data);
        out.push(ct);
        let nonce = self.nonce();
        let (hdr, body) = out[start..].split_at_mut(5);
        let tag = match &self.aead {
            Aead::ChaCha(c) => c.seal(&nonce, hdr, body),
            Aead::Aes(a) => a.seal(&nonce, hdr, body),
        };
        out.extend_from_slice(&tag);
        self.seq += 1;
    }

    /// Decrypts a record body in place; returns (content type, plaintext length).
    fn open(&mut self, hdr: &[u8; 5], body: &mut [u8]) -> io::Result<(u8, usize)> {
        if body.len() < 17 {
            return Err(tls_err("record too short"));
        }
        let (ct, tag) = body.split_at_mut(body.len() - 16);
        let nonce = self.nonce();
        let ok = match &self.aead {
            Aead::ChaCha(c) => c.open(&nonce, hdr, ct, tag),
            Aead::Aes(a) => a.open(&nonce, hdr, ct, tag),
        };
        if !ok {
            return Err(tls_err("bad record MAC (decryption failed)"));
        }
        self.seq += 1;
        let mut n = ct.len();
        while n > 0 && ct[n - 1] == 0 {
            n -= 1;
        }
        if n == 0 {
            return Err(tls_err("record has no content type"));
        }
        Ok((ct[n - 1], n - 1))
    }
}

/// A TLS 1.3 client connection over TCP. Implements `Read` + `Write`.
pub struct TlsStream {
    sock: TcpStream,
    read: Option<Protection>,
    write: Option<Protection>,
    inbuf: Vec<u8>,
    in_start: usize,
    plain: Vec<u8>,
    plain_pos: usize,
    hs: Vec<u8>,
    got_close_notify: bool,
    closed: bool,
    suite: Option<Suite>,
}

fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn with_u16_len(v: &mut Vec<u8>, f: impl FnOnce(&mut Vec<u8>)) {
    let at = v.len();
    v.extend_from_slice(&[0, 0]);
    f(v);
    let n = (v.len() - at - 2) as u16;
    v[at..at + 2].copy_from_slice(&n.to_be_bytes());
}

/// Simple bounds-checked reader for handshake structures.
struct Cur<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn new(d: &'a [u8]) -> Self {
        Cur { d, p: 0 }
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.p + n > self.d.len() {
            return Err(tls_err("decode error: message truncated"));
        }
        let s = &self.d[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> io::Result<usize> {
        let b = self.take(3)?;
        Ok((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
    fn vec8(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn vec24(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u24()?;
        self.take(n)
    }
    fn done(&self) -> bool {
        self.p >= self.d.len()
    }
}

fn hs_msg(t: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + body.len());
    m.push(t);
    let n = body.len();
    m.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    m.extend_from_slice(body);
    m
}

fn build_client_hello(host: &str, random: &[u8; 32], session_id: &[u8; 32], pubkey: &[u8; 32], cookie: Option<&[u8]>) -> Vec<u8> {
    let mut b = Vec::with_capacity(512);
    put_u16(&mut b, 0x0303);
    b.extend_from_slice(random);
    b.push(32);
    b.extend_from_slice(session_id);
    with_u16_len(&mut b, |b| {
        for s in [SUITE_CHACHA, SUITE_AES128, SUITE_AES256] {
            put_u16(b, s);
        }
    });
    b.extend_from_slice(&[1, 0]); // compression: null
    with_u16_len(&mut b, |b| {
        // server_name (only for DNS names)
        let is_ip = host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[');
        if !is_ip {
            put_u16(b, 0x0000);
            with_u16_len(b, |b| {
                with_u16_len(b, |b| {
                    b.push(0);
                    with_u16_len(b, |b| b.extend_from_slice(host.trim_end_matches('.').as_bytes()));
                });
            });
        }
        // supported_groups
        put_u16(b, 0x000a);
        with_u16_len(b, |b| with_u16_len(b, |b| put_u16(b, GROUP_X25519)));
        // signature_algorithms
        put_u16(b, 0x000d);
        with_u16_len(b, |b| {
            with_u16_len(b, |b| {
                for &s in SIG_ALGS {
                    put_u16(b, s);
                }
            })
        });
        // supported_versions: TLS 1.3 only
        put_u16(b, 0x002b);
        with_u16_len(b, |b| {
            b.push(2);
            put_u16(b, 0x0304);
        });
        // key_share
        put_u16(b, 0x0033);
        with_u16_len(b, |b| {
            with_u16_len(b, |b| {
                put_u16(b, GROUP_X25519);
                with_u16_len(b, |b| b.extend_from_slice(pubkey));
            })
        });
        // cookie (after HelloRetryRequest)
        if let Some(c) = cookie {
            put_u16(b, 0x002c);
            with_u16_len(b, |b| with_u16_len(b, |b| b.extend_from_slice(c)));
        }
    });
    hs_msg(HT_CLIENT_HELLO, &b)
}

struct ServerHello {
    random: [u8; 32],
    suite: u16,
    key_share: Option<(u16, Vec<u8>)>,
    hrr_group: Option<u16>,
    cookie: Option<Vec<u8>>,
    version: Option<u16>,
}

fn parse_server_hello(body: &[u8], session_id: &[u8; 32]) -> io::Result<ServerHello> {
    let mut c = Cur::new(body);
    let _legacy = c.u16()?;
    let mut random = [0u8; 32];
    random.copy_from_slice(c.take(32)?);
    let sid = c.vec8()?;
    let suite = c.u16()?;
    let _comp = c.u8()?;
    let mut sh = ServerHello { random, suite, key_share: None, hrr_group: None, cookie: None, version: None };
    let is_hrr = random == HRR_RANDOM;
    if c.done() {
        return Ok(sh); // TLS <= 1.2 server without extensions
    }
    let exts = c.vec16()?;
    let mut e = Cur::new(exts);
    while !e.done() {
        let t = e.u16()?;
        let v = e.vec16()?;
        let mut vc = Cur::new(v);
        match t {
            0x002b => sh.version = Some(vc.u16()?),
            0x0033 => {
                if is_hrr {
                    sh.hrr_group = Some(vc.u16()?);
                } else {
                    let g = vc.u16()?;
                    let k = vc.vec16()?.to_vec();
                    sh.key_share = Some((g, k));
                }
            }
            0x002c => sh.cookie = Some(vc.vec16()?.to_vec()),
            _ => {}
        }
    }
    if sh.version == Some(0x0304) && sid != session_id {
        return Err(tls_err("illegal parameter: session id echo mismatch"));
    }
    Ok(sh)
}

impl TlsStream {
    /// Connects to `host:port` and performs a full TLS 1.3 handshake, validating the
    /// server certificate chain against `roots` and `host`.
    pub fn connect(host: &str, port: u16, roots: &Arc<RootStore>, timeout: Duration) -> io::Result<TlsStream> {
        let addrs: Vec<_> = (host.trim_start_matches('[').trim_end_matches(']'), port).to_socket_addrs()?.collect();
        if addrs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("could not resolve {host}")));
        }
        let mut last = None;
        let mut sock = None;
        for a in addrs {
            match TcpStream::connect_timeout(&a, timeout) {
                Ok(s) => {
                    sock = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let sock = match sock {
            Some(s) => s,
            None => return Err(last.unwrap()),
        };
        sock.set_nodelay(true)?;
        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(timeout))?;
        Self::handshake(sock, host, roots)
    }

    /// Performs the handshake over an already-connected socket.
    pub fn handshake(sock: TcpStream, host: &str, roots: &RootStore) -> io::Result<TlsStream> {
        let mut s = TlsStream {
            sock,
            read: None,
            write: None,
            inbuf: Vec::with_capacity(32 * 1024),
            in_start: 0,
            plain: Vec::new(),
            plain_pos: 0,
            hs: Vec::new(),
            got_close_notify: false,
            closed: false,
            suite: None,
        };
        let host_clean = host.trim_start_matches('[').trim_end_matches(']');
        match s.do_handshake(host_clean, roots) {
            Ok(()) => Ok(s),
            Err(e) => {
                // Best effort: tell the server why (unencrypted alerts are fine before keys).
                let code = if e.to_string().contains("unknown issuer") {
                    48
                } else if e.to_string().contains("expired") {
                    45
                } else if e.to_string().contains("certificate") || e.to_string().contains("hostname") {
                    42
                } else {
                    40
                };
                let _ = s.send_alert(code);
                Err(e)
            }
        }
    }

    /// Negotiated cipher suite name.
    pub fn cipher_suite(&self) -> &'static str {
        self.suite.map(|s| s.name()).unwrap_or("")
    }

    pub fn get_ref(&self) -> &TcpStream {
        &self.sock
    }

    pub fn set_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(t)?;
        self.sock.set_write_timeout(t)
    }

    fn do_handshake(&mut self, host: &str, roots: &RootStore) -> io::Result<()> {
        let secret: [u8; 32] = random::array()?;
        let pubkey = x25519::public_key(&secret);
        let client_random: [u8; 32] = random::array()?;
        let session_id: [u8; 32] = random::array()?;

        let ch1 = build_client_hello(host, &client_random, &session_id, &pubkey, None);
        self.send_plain_record(CT_HANDSHAKE, &ch1, true)?;
        let mut transcript: Vec<u8> = ch1.clone();

        let (mut sh_msg, mut sh) = self.read_server_hello(&session_id)?;
        if sh.random == HRR_RANDOM {
            if sh.version != Some(0x0304) {
                return Err(tls_err("server does not support TLS 1.3"));
            }
            if let Some(g) = sh.hrr_group {
                if g != GROUP_X25519 {
                    return Err(tls_err(format!(
                        "server requires an unsupported key exchange group (0x{g:04x}); only X25519 is supported"
                    )));
                }
                if sh.cookie.is_none() {
                    return Err(tls_err("illegal HelloRetryRequest"));
                }
            }
            let suite = Suite::from_id(sh.suite).ok_or_else(|| tls_err("server chose an unsupported cipher suite"))?;
            // transcript = message_hash(CH1) || HRR || CH2
            let h = suite.hash.hash(&ch1);
            transcript = hs_msg(HT_MESSAGE_HASH, &h);
            transcript.extend_from_slice(&sh_msg);
            // middlebox compatibility CCS, then the second ClientHello
            self.sock.write_all(&[CT_CCS, 3, 3, 0, 1, 1])?;
            let ch2 = build_client_hello(host, &client_random, &session_id, &pubkey, sh.cookie.as_deref());
            self.send_plain_record(CT_HANDSHAKE, &ch2, false)?;
            transcript.extend_from_slice(&ch2);
            let r = self.read_server_hello(&session_id)?;
            sh_msg = r.0;
            sh = r.1;
            if sh.random == HRR_RANDOM {
                return Err(tls_err("unexpected second HelloRetryRequest"));
            }
        } else {
            // send the compatibility CCS before our encrypted flight later
        }
        if sh.version != Some(0x0304) {
            return Err(tls_err("server does not support TLS 1.3 (TLS 1.2 and older are not supported)"));
        }
        let suite = Suite::from_id(sh.suite).ok_or_else(|| tls_err("server chose an unsupported cipher suite"))?;
        self.suite = Some(suite);
        let (group, server_pub) = sh.key_share.clone().ok_or_else(|| tls_err("missing key_share extension"))?;
        if group != GROUP_X25519 || server_pub.len() != 32 {
            return Err(tls_err("server chose an unsupported key exchange group"));
        }
        transcript.extend_from_slice(&sh_msg);

        let mut sp = [0u8; 32];
        sp.copy_from_slice(&server_pub);
        let shared = x25519::x25519(&secret, &sp);
        if shared == [0u8; 32] {
            return Err(tls_err("illegal parameter: invalid X25519 public key"));
        }

        let alg = suite.hash;
        let hl = alg.output_len();
        let zeros = vec![0u8; hl];
        let early = hkdf::extract(alg, &zeros, &zeros);
        let empty_hash = alg.hash(&[]);
        let derived = derive_secret(alg, &early, "derived", &empty_hash);
        let hs_secret = hkdf::extract(alg, &derived, &shared);
        let th = alg.hash(&transcript);
        let c_hs = derive_secret(alg, &hs_secret, "c hs traffic", &th);
        let s_hs = derive_secret(alg, &hs_secret, "s hs traffic", &th);
        let derived2 = derive_secret(alg, &hs_secret, "derived", &empty_hash);
        let master = hkdf::extract(alg, &derived2, &zeros);

        if !self.hs.is_empty() {
            return Err(tls_err("unexpected message: handshake data across key change"));
        }
        self.read = Some(Protection::new(suite, s_hs.clone()));

        // EncryptedExtensions
        let (t, m) = self.read_hs_message()?;
        if t != HT_ENCRYPTED_EXTENSIONS {
            return Err(tls_err(format!("unexpected handshake message {t} (expected EncryptedExtensions)")));
        }
        transcript.extend_from_slice(&m);

        // optional CertificateRequest, then Certificate
        let (mut t, mut m) = self.read_hs_message()?;
        let mut cert_request_ctx: Option<Vec<u8>> = None;
        if t == HT_CERTIFICATE_REQUEST {
            let mut c = Cur::new(&m[4..]);
            cert_request_ctx = Some(c.vec8()?.to_vec());
            transcript.extend_from_slice(&m);
            let r = self.read_hs_message()?;
            t = r.0;
            m = r.1;
        }
        if t != HT_CERTIFICATE {
            return Err(tls_err(format!("unexpected handshake message {t} (expected Certificate)")));
        }
        let mut chain = Vec::new();
        {
            let mut c = Cur::new(&m[4..]);
            let _ctx = c.vec8()?;
            let list = c.vec24()?;
            let mut lc = Cur::new(list);
            while !lc.done() {
                chain.push(lc.vec24()?.to_vec());
                let _exts = lc.vec16()?;
                if chain.len() > 16 {
                    return Err(tls_err("certificate chain too long"));
                }
            }
        }
        transcript.extend_from_slice(&m);
        let leaf = x509::verify_server_chain(&chain, roots, host, x509::now_unix()).map_err(tls_err)?;

        // CertificateVerify
        let (t, m) = self.read_hs_message()?;
        if t != HT_CERTIFICATE_VERIFY {
            return Err(tls_err(format!("unexpected handshake message {t} (expected CertificateVerify)")));
        }
        {
            let mut c = Cur::new(&m[4..]);
            let scheme = c.u16()?;
            let sig = c.vec16()?;
            let mut content = vec![0x20u8; 64];
            content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
            content.extend_from_slice(&alg.hash(&transcript));
            let key = leaf.public_key.as_ref().ok_or_else(|| tls_err("unsupported server public key"))?;
            if !verify_cert_verify(key, scheme, &content, sig) {
                return Err(tls_err("decrypt error: server CertificateVerify signature is invalid"));
            }
        }
        transcript.extend_from_slice(&m);

        // Server Finished
        let (t, m) = self.read_hs_message()?;
        if t != HT_FINISHED {
            return Err(tls_err(format!("unexpected handshake message {t} (expected Finished)")));
        }
        let s_fin_key = expand_label(alg, &s_hs, "finished", &[], hl);
        let expect = hmac(alg, &s_fin_key, &alg.hash(&transcript));
        if !ct_eq(&expect, &m[4..]) {
            return Err(tls_err("decrypt error: server Finished verification failed"));
        }
        transcript.extend_from_slice(&m);
        let th_sf = alg.hash(&transcript);
        let c_ap = derive_secret(alg, &master, "c ap traffic", &th_sf);
        let s_ap = derive_secret(alg, &master, "s ap traffic", &th_sf);
        if !self.hs.is_empty() {
            return Err(tls_err("unexpected message: handshake data across key change"));
        }

        // Client flight: CCS (compat), [empty Certificate], Finished
        let mut out = Vec::new();
        out.extend_from_slice(&[CT_CCS, 3, 3, 0, 1, 1]);
        let mut wp = Protection::new(suite, c_hs.clone());
        if let Some(ctx) = cert_request_ctx {
            let mut body = Vec::new();
            body.push(ctx.len() as u8);
            body.extend_from_slice(&ctx);
            body.extend_from_slice(&[0, 0, 0]);
            let cm = hs_msg(HT_CERTIFICATE, &body);
            transcript.extend_from_slice(&cm);
            wp.seal(CT_HANDSHAKE, &cm, &mut out);
        }
        let c_fin_key = expand_label(alg, &c_hs, "finished", &[], hl);
        let fin = hs_msg(HT_FINISHED, &hmac(alg, &c_fin_key, &alg.hash(&transcript)));
        wp.seal(CT_HANDSHAKE, &fin, &mut out);
        self.sock.write_all(&out)?;

        self.read = Some(Protection::new(suite, s_ap));
        self.write = Some(Protection::new(suite, c_ap));
        Ok(())
    }

    fn read_server_hello(&mut self, session_id: &[u8; 32]) -> io::Result<(Vec<u8>, ServerHello)> {
        let (t, m) = self.read_hs_message().map_err(|e| {
            let msg = e.to_string();
            if msg.contains("handshake_failure") || msg.contains("protocol_version") {
                tls_err(format!("{msg} (the server may not support TLS 1.3, which this client requires)"))
            } else {
                e
            }
        })?;
        if t != HT_SERVER_HELLO {
            return Err(tls_err(format!("unexpected handshake message {t} (expected ServerHello)")));
        }
        let sh = parse_server_hello(&m[4..], session_id)?;
        Ok((m, sh))
    }

    fn send_plain_record(&mut self, ct: u8, data: &[u8], first: bool) -> io::Result<()> {
        let mut out = Vec::with_capacity(data.len() + 5);
        for chunk in data.chunks(MAX_PLAINTEXT) {
            out.extend_from_slice(&[ct, 3, if first { 1 } else { 3 }, (chunk.len() >> 8) as u8, chunk.len() as u8]);
            out.extend_from_slice(chunk);
        }
        self.sock.write_all(&out)
    }

    fn send_alert(&mut self, code: u8) -> io::Result<()> {
        let level = if code == 0 { 1 } else { 2 };
        match self.write.as_mut() {
            Some(w) => {
                let mut out = Vec::new();
                w.seal(CT_ALERT, &[level, code], &mut out);
                self.sock.write_all(&out)
            }
            None => self.sock.write_all(&[CT_ALERT, 3, 3, 0, 2, level, code]),
        }
    }

    /// Ensures at least `n` unread bytes are buffered. Returns false on clean EOF at a record boundary.
    fn fill(&mut self, n: usize) -> io::Result<bool> {
        while self.inbuf.len() - self.in_start < n {
            if self.in_start > 0 {
                self.inbuf.drain(..self.in_start);
                self.in_start = 0;
            }
            let old = self.inbuf.len();
            self.inbuf.resize(old + 32 * 1024, 0);
            let r = self.sock.read(&mut self.inbuf[old..]);
            match r {
                Ok(0) => {
                    self.inbuf.truncate(old);
                    if old == 0 {
                        return Ok(false);
                    }
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TLS: connection closed mid-record"));
                }
                Ok(k) => self.inbuf.truncate(old + k),
                Err(e) => {
                    self.inbuf.truncate(old);
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Ok(true)
    }

    /// Reads one record, decrypting if keys are installed. Returns (content type, payload).
    fn read_record(&mut self) -> io::Result<(u8, Vec<u8>)> {
        loop {
            if !self.fill(5)? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS: connection closed by peer without close_notify",
                ));
            }
            let s = self.in_start;
            let hdr: [u8; 5] = self.inbuf[s..s + 5].try_into().unwrap();
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            if len > MAX_PLAINTEXT + 256 {
                return Err(tls_err("record overflow"));
            }
            if !self.fill(5 + len)? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TLS: truncated record"));
            }
            let s = self.in_start;
            let mut body = self.inbuf[s + 5..s + 5 + len].to_vec();
            self.in_start += 5 + len;
            let ct = hdr[0];
            match ct {
                CT_CCS => {
                    if self.write.is_some() || body != [1] {
                        return Err(tls_err("unexpected ChangeCipherSpec"));
                    }
                    continue; // compatibility mode: ignore
                }
                CT_APP if self.read.is_some() => {
                    let (inner, n) = self.read.as_mut().unwrap().open(&hdr, &mut body)?;
                    body.truncate(n);
                    if n > MAX_PLAINTEXT {
                        return Err(tls_err("record overflow"));
                    }
                    return Ok((inner, body));
                }
                CT_ALERT | CT_HANDSHAKE if self.read.is_none() => return Ok((ct, body)),
                CT_ALERT if self.write.is_none() && body.len() == 2 => return Ok((ct, body)),
                _ => return Err(tls_err(format!("unexpected record type {ct}"))),
            }
        }
    }

    fn handle_alert(&mut self, body: &[u8]) -> io::Result<()> {
        if body.len() != 2 {
            return Err(tls_err("malformed alert"));
        }
        if body[1] == 0 {
            self.got_close_notify = true;
            return Ok(());
        }
        Err(tls_err(format!("server sent alert: {} ({})", alert_name(body[1]), body[1])))
    }

    /// Next complete handshake message (type, full encoding incl. 4-byte header).
    fn read_hs_message(&mut self) -> io::Result<(u8, Vec<u8>)> {
        loop {
            if self.hs.len() >= 4 {
                let n = (self.hs[1] as usize) << 16 | (self.hs[2] as usize) << 8 | self.hs[3] as usize;
                if n > 1 << 18 {
                    return Err(tls_err("handshake message too large"));
                }
                if self.hs.len() >= 4 + n {
                    let m: Vec<u8> = self.hs.drain(..4 + n).collect();
                    return Ok((m[0], m));
                }
            }
            let (ct, body) = self.read_record()?;
            match ct {
                CT_HANDSHAKE => {
                    if body.is_empty() {
                        return Err(tls_err("empty handshake record"));
                    }
                    self.hs.extend_from_slice(&body)
                }
                CT_ALERT => {
                    self.handle_alert(&body)?;
                    return Err(tls_err("connection closed during handshake"));
                }
                _ => return Err(tls_err(format!("unexpected content type {ct} during handshake"))),
            }
        }
    }

    fn process_post_handshake(&mut self) -> io::Result<()> {
        while self.hs.len() >= 4 {
            let n = (self.hs[1] as usize) << 16 | (self.hs[2] as usize) << 8 | self.hs[3] as usize;
            if self.hs.len() < 4 + n {
                break;
            }
            let m: Vec<u8> = self.hs.drain(..4 + n).collect();
            match m[0] {
                HT_NEW_SESSION_TICKET => {} // resumption not supported: ignore
                HT_KEY_UPDATE => {
                    if n != 1 {
                        return Err(tls_err("malformed KeyUpdate"));
                    }
                    self.read.as_mut().unwrap().update();
                    if m[4] == 1 {
                        let mut out = Vec::new();
                        let w = self.write.as_mut().unwrap();
                        w.seal(CT_HANDSHAKE, &hs_msg(HT_KEY_UPDATE, &[0]), &mut out);
                        w.update();
                        self.sock.write_all(&out)?;
                    }
                }
                t => return Err(tls_err(format!("unexpected post-handshake message {t}"))),
            }
        }
        Ok(())
    }

    /// Sends close_notify and shuts down the write side.
    pub fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.send_alert(0);
            let _ = self.sock.flush();
            let _ = self.sock.shutdown(std::net::Shutdown::Write);
        }
    }
}

fn verify_cert_verify(key: &PublicKey, scheme: u16, content: &[u8], sig: &[u8]) -> bool {
    match (scheme, key) {
        (0x0804, PublicKey::Rsa(k)) => k.verify_pss(HashAlg::Sha256, &HashAlg::Sha256.hash(content), sig, Some(32)),
        (0x0805, PublicKey::Rsa(k)) => k.verify_pss(HashAlg::Sha384, &HashAlg::Sha384.hash(content), sig, Some(48)),
        (0x0806, PublicKey::Rsa(k)) => k.verify_pss(HashAlg::Sha512, &HashAlg::Sha512.hash(content), sig, Some(64)),
        (0x0403, PublicKey::Ec(Curve::P256, pt)) => ecdsa::verify(Curve::P256, pt, &HashAlg::Sha256.hash(content), sig),
        (0x0503, PublicKey::Ec(Curve::P384, pt)) => ecdsa::verify(Curve::P384, pt, &HashAlg::Sha384.hash(content), sig),
        _ => false,
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.plain_pos < self.plain.len() {
                let n = buf.len().min(self.plain.len() - self.plain_pos);
                buf[..n].copy_from_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
                self.plain_pos += n;
                return Ok(n);
            }
            if self.got_close_notify {
                return Ok(0);
            }
            let (ct, body) = self.read_record()?;
            match ct {
                CT_APP => {
                    self.plain = body;
                    self.plain_pos = 0;
                }
                CT_HANDSHAKE => {
                    self.hs.extend_from_slice(&body);
                    self.process_post_handshake()?;
                }
                CT_ALERT => self.handle_alert(&body)?,
                _ => return Err(tls_err(format!("unexpected content type {ct}"))),
            }
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "TLS: connection closed"));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        // Batch several records per syscall for throughput.
        let n = buf.len().min(4 * MAX_PLAINTEXT);
        let mut out = Vec::with_capacity(n + 4 * 22);
        let w = self.write.as_mut().ok_or_else(|| tls_err("handshake not complete"))?;
        for chunk in buf[..n].chunks(MAX_PLAINTEXT) {
            w.seal(CT_APP, chunk, &mut out);
        }
        self.sock.write_all(&out)?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::util::{hex, unhex};

    #[test]
    fn rfc8448_key_schedule() {
        let alg = HashAlg::Sha256;
        let zeros = [0u8; 32];
        let early = hkdf::extract(alg, &zeros, &zeros);
        assert_eq!(hex(&early), "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        let derived = derive_secret(alg, &early, "derived", &alg.hash(&[]));
        assert_eq!(hex(&derived), "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        let shared = unhex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d").unwrap();
        let hs = hkdf::extract(alg, &derived, &shared);
        assert_eq!(hex(&hs), "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
        let th = unhex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8").unwrap();
        let c_hs = derive_secret(alg, &hs, "c hs traffic", &th);
        let s_hs = derive_secret(alg, &hs, "s hs traffic", &th);
        assert_eq!(hex(&c_hs), "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
        assert_eq!(hex(&s_hs), "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
        assert_eq!(hex(&expand_label(alg, &s_hs, "key", &[], 16)), "3fce516009c21727d0f2e4e86ee403bc");
        assert_eq!(hex(&expand_label(alg, &s_hs, "iv", &[], 12)), "5d313eb2671276ee13000b30");
        let d2 = derive_secret(alg, &hs, "derived", &alg.hash(&[]));
        assert_eq!(hex(&d2), "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4");
        let master = hkdf::extract(alg, &d2, &zeros);
        assert_eq!(hex(&master), "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
        // X25519 from RFC 8448: server private key and client public key give the shared secret.
        let sk: [u8; 32] = unhex("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e").unwrap().try_into().unwrap();
        let cp: [u8; 32] = unhex("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c").unwrap().try_into().unwrap();
        assert_eq!(x25519::x25519(&sk, &cp).to_vec(), shared);
    }

    #[test]
    fn record_roundtrip() {
        for id in [SUITE_CHACHA, SUITE_AES128, SUITE_AES256] {
            let suite = Suite::from_id(id).unwrap();
            let mut w = Protection::new(suite, vec![7u8; suite.hash.output_len()]);
            let mut r = Protection::new(suite, vec![7u8; suite.hash.output_len()]);
            for msg in [&b"hello"[..], &[0u8; 1000][..], &b""[..]] {
                let mut out = Vec::new();
                w.seal(CT_APP, msg, &mut out);
                let hdr: [u8; 5] = out[..5].try_into().unwrap();
                let mut body = out[5..].to_vec();
                let (ct, n) = r.open(&hdr, &mut body).unwrap();
                assert_eq!(ct, CT_APP);
                assert_eq!(&body[..n], msg);
            }
            w.update();
            r.update();
            let mut out = Vec::new();
            w.seal(CT_HANDSHAKE, b"x", &mut out);
            let hdr: [u8; 5] = out[..5].try_into().unwrap();
            let mut body = out[5..].to_vec();
            body[0] ^= 1;
            assert!(r.open(&hdr, &mut body).is_err());
        }
    }
}
