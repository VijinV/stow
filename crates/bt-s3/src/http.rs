//! Minimal HTTP/1.1 client with keep-alive connection pooling.
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A bidirectional byte stream (plain TCP or TLS).
pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// Pluggable TLS: connect to `host:port` and return an encrypted stream.
pub trait TlsConnector: Send + Sync {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> io::Result<Box<dyn Stream>>;
}

/// Connector used when no TLS implementation is available.
pub struct NoTls;
impl TlsConnector for NoTls {
    fn connect(&self, host: &str, _: u16, _: Duration) -> io::Result<Box<dyn Stream>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, format!("HTTPS is not available (connecting to {})", host)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    /// Host without IPv6 brackets.
    pub host: String,
    pub port: u16,
    /// Already-encoded path, starts with '/'.
    pub path: String,
    /// Already-encoded query without '?'.
    pub query: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url, String> {
        let s = s.trim();
        let (scheme, rest) = s.split_once("://").ok_or_else(|| format!("'{}' is not a URL (missing http:// or https://)", s))?;
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            _ => return Err(format!("unsupported URL scheme '{}'", scheme)),
        };
        let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, pathq) = rest.split_at(split);
        let authority = authority.rsplit_once('@').map(|x| x.1).unwrap_or(authority);
        let (host, port_str) = if let Some(a) = authority.strip_prefix('[') {
            let end = a.find(']').ok_or("unterminated IPv6 address")?;
            (&a[..end], a[end + 1..].strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        if host.is_empty() {
            return Err("URL has no host".into());
        }
        let port = match port_str {
            Some(p) if !p.is_empty() => p.parse::<u16>().map_err(|_| format!("bad port '{}'", p))?,
            _ => default_port,
        };
        let pathq = pathq.split('#').next().unwrap_or("");
        let (path, query) = match pathq.split_once('?') {
            Some((p, q)) => (p, q),
            None => (pathq, ""),
        };
        Ok(Url {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
            path: if path.is_empty() { "/".into() } else { path.into() },
            query: query.into(),
        })
    }

    pub fn default_port(&self) -> u16 {
        if self.scheme == "https" { 443 } else { 80 }
    }

    pub fn is_https(&self) -> bool {
        self.scheme == "https"
    }

    /// Value for the `Host` header.
    pub fn host_header(&self) -> String {
        let h = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == self.default_port() { h } else { format!("{}:{}", h, self.port) }
    }

    pub fn request_target(&self) -> String {
        if self.query.is_empty() { self.path.clone() } else { format!("{}?{}", self.path, self.query) }
    }

    /// True for IP literals and localhost names (S3 endpoints that need path-style).
    pub fn is_ip_or_localhost(&self) -> bool {
        self.host == "localhost"
            || self.host.ends_with(".localhost")
            || self.host.parse::<std::net::IpAddr>().is_ok()
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}{}", self.scheme, self.host_header(), self.request_target())
    }
}

/// Request body that can be (re)opened for each attempt.
pub trait Body: Sync {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn open(&self) -> io::Result<Box<dyn Read + '_>>;
}

pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a Url,
    pub headers: &'a [(String, String)],
    pub body: Option<&'a dyn Body>,
    pub cancel: Option<&'a AtomicBool>,
}

#[derive(Debug, Clone, Default)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    /// Body, unless it was streamed into a sink (2xx with sink given).
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

struct Conn {
    stream: Box<dyn Stream>,
    buf: Box<[u8]>,
    pos: usize,
    len: usize,
    idle_since: Instant,
}

const MAX_LINE: usize = 64 * 1024;

impl Conn {
    fn new(stream: Box<dyn Stream>) -> Conn {
        Conn { stream, buf: vec![0u8; 64 * 1024].into_boxed_slice(), pos: 0, len: 0, idle_since: Instant::now() }
    }

    fn fill(&mut self) -> io::Result<usize> {
        if self.pos == self.len {
            self.pos = 0;
            self.len = 0;
            loop {
                match self.stream.read(&mut self.buf) {
                    Ok(n) => {
                        self.len = n;
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(self.len - self.pos)
    }

    fn read_line(&mut self) -> io::Result<String> {
        let mut line = Vec::new();
        loop {
            if self.fill()? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed by server"));
            }
            let avail = &self.buf[self.pos..self.len];
            if let Some(i) = avail.iter().position(|&c| c == b'\n') {
                line.extend_from_slice(&avail[..i]);
                self.pos += i + 1;
                break;
            }
            line.extend_from_slice(avail);
            self.pos = self.len;
            if line.len() > MAX_LINE {
                return Err(bad("HTTP line too long"));
            }
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        String::from_utf8(line).map_err(|_| bad("non-UTF-8 HTTP header"))
    }

    fn read_exact_to(&mut self, mut n: u64, out: &mut dyn FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
        while n > 0 {
            if self.fill()? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "response body truncated"));
            }
            let take = ((self.len - self.pos) as u64).min(n) as usize;
            out(&self.buf[self.pos..self.pos + take])?;
            self.pos += take;
            n -= take as u64;
        }
        Ok(())
    }

    fn read_to_eof(&mut self, out: &mut dyn FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
        loop {
            match self.fill() {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    out(&self.buf[self.pos..self.len])?;
                    self.pos = self.len;
                }
                // Some servers reset instead of closing cleanly after the body.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

pub struct HttpClient {
    tls: Arc<dyn TlsConnector>,
    pool: Mutex<HashMap<String, Vec<Conn>>>,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub user_agent: String,
}

const POOL_PER_HOST: usize = 16;
const POOL_IDLE: Duration = Duration::from_secs(15);

impl HttpClient {
    pub fn new(tls: Arc<dyn TlsConnector>) -> HttpClient {
        HttpClient {
            tls,
            pool: Mutex::new(HashMap::new()),
            connect_timeout: Duration::from_secs(15),
            io_timeout: Duration::from_secs(90),
            user_agent: concat!("backup-taker/", env!("CARGO_PKG_VERSION")).to_string(),
        }
    }

    fn pool_key(url: &Url) -> String {
        format!("{}://{}:{}", url.scheme, url.host, url.port)
    }

    fn take_pooled(&self, key: &str) -> Option<Conn> {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        let v = pool.get_mut(key)?;
        while let Some(c) = v.pop() {
            if c.idle_since.elapsed() < POOL_IDLE {
                return Some(c);
            }
        }
        None
    }

    fn put_back(&self, key: String, mut c: Conn) {
        c.idle_since = Instant::now();
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        let v = pool.entry(key).or_default();
        if v.len() < POOL_PER_HOST {
            v.push(c);
        }
    }

    /// Drop all pooled connections.
    pub fn clear_pool(&self) {
        self.pool.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn connect(&self, url: &Url) -> io::Result<Conn> {
        if url.is_https() {
            return Ok(Conn::new(self.tls.connect(&url.host, url.port, self.connect_timeout)?));
        }
        let addrs: Vec<_> = (url.host.as_str(), url.port).to_socket_addrs()?.collect();
        let mut last = io::Error::new(io::ErrorKind::NotFound, format!("could not resolve {}", url.host));
        for a in addrs {
            match TcpStream::connect_timeout(&a, self.connect_timeout) {
                Ok(s) => {
                    s.set_read_timeout(Some(self.io_timeout))?;
                    s.set_write_timeout(Some(self.io_timeout))?;
                    let _ = s.set_nodelay(true);
                    return Ok(Conn::new(Box::new(s)));
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Send a request. A 2xx response body is streamed into `sink` when given;
    /// otherwise (or for non-2xx) it is collected in `Response::body`.
    /// `progress` receives byte deltas of the uploaded body and the downloaded
    /// sink data. A pooled connection that turns out to be stale is retried once.
    pub fn send(&self, req: &Request, mut sink: Option<&mut dyn Write>, progress: &mut dyn FnMut(u64)) -> io::Result<Response> {
        let key = Self::pool_key(req.url);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let (mut conn, reused) = match self.take_pooled(&key) {
                Some(c) => (c, true),
                None => (self.connect(req.url)?, false),
            };
            let mut got_response = false;
            let s: Option<&mut dyn Write> = match sink {
                Some(ref mut s) => Some(&mut **s),
                None => None,
            };
            match self.exchange(&mut conn, req, s, progress, &mut got_response) {
                Ok((resp, reusable)) => {
                    if reusable {
                        self.put_back(key, conn);
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    let cancelled = req.cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false);
                    if reused && !got_response && !cancelled && attempt < 3 {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    fn exchange(
        &self,
        conn: &mut Conn,
        req: &Request,
        sink: Option<&mut dyn Write>,
        progress: &mut dyn FnMut(u64),
        got_response: &mut bool,
    ) -> io::Result<(Response, bool)> {
        let mut head = format!("{} {} HTTP/1.1\r\n", req.method, req.url.request_target());
        let has = |n: &str| req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
        if !has("host") {
            head.push_str(&format!("Host: {}\r\n", req.url.host_header()));
        }
        for (k, v) in req.headers {
            if k.contains(['\r', '\n', ':']) || v.contains(['\r', '\n']) {
                return Err(bad("invalid character in HTTP header"));
            }
            head.push_str(&format!("{}: {}\r\n", k, v));
        }
        let body_len = req.body.map(|b| b.len()).unwrap_or(0);
        if !has("content-length") && (req.body.is_some() || matches!(req.method, "PUT" | "POST")) {
            head.push_str(&format!("Content-Length: {}\r\n", body_len));
        }
        if !has("user-agent") {
            head.push_str(&format!("User-Agent: {}\r\n", self.user_agent));
        }
        head.push_str("\r\n");

        let write_result = (|| -> io::Result<()> {
            let mut out = Vec::with_capacity(head.len() + 64 * 1024);
            out.extend_from_slice(head.as_bytes());
            if let Some(body) = req.body {
                let mut r = body.open()?;
                let mut remaining = body_len;
                let mut buf = vec![0u8; 64 * 1024];
                while remaining > 0 {
                    if req.cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                        return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                    }
                    let want = (buf.len() as u64).min(remaining) as usize;
                    let n = r.read(&mut buf[..want])?;
                    if n == 0 {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "file became shorter while uploading"));
                    }
                    out.extend_from_slice(&buf[..n]);
                    conn.stream.write_all(&out)?;
                    out.clear();
                    remaining -= n as u64;
                    progress(n as u64);
                }
            }
            if !out.is_empty() {
                conn.stream.write_all(&out)?;
            }
            conn.stream.flush()
        })();

        if let Err(e) = write_result {
            if e.kind() == io::ErrorKind::Interrupted {
                return Err(e);
            }
            // The server may have answered early (e.g. auth error) and closed.
            return match self.read_response(conn, req, None, progress, got_response) {
                Ok((resp, _)) if *got_response => Ok((resp, false)),
                _ => Err(e),
            };
        }
        self.read_response(conn, req, sink, progress, got_response)
    }

    fn read_response(
        &self,
        conn: &mut Conn,
        req: &Request,
        sink: Option<&mut dyn Write>,
        progress: &mut dyn FnMut(u64),
        got_response: &mut bool,
    ) -> io::Result<(Response, bool)> {
        let (resp_line, headers) = loop {
            let line = conn.read_line()?;
            *got_response = true;
            let mut parts = line.splitn(3, ' ');
            let version = parts.next().unwrap_or("");
            if !version.starts_with("HTTP/") {
                return Err(bad("malformed HTTP status line"));
            }
            let status: u16 = parts.next().unwrap_or("").parse().map_err(|_| bad("malformed HTTP status code"))?;
            let reason = parts.next().unwrap_or("").to_string();
            let mut headers = Vec::new();
            loop {
                let l = conn.read_line()?;
                if l.is_empty() {
                    break;
                }
                if let Some((k, v)) = l.split_once(':') {
                    headers.push((k.trim().to_string(), v.trim().to_string()));
                }
                if headers.len() > 500 {
                    return Err(bad("too many HTTP headers"));
                }
            }
            if (100..200).contains(&status) && status != 101 {
                continue;
            }
            break ((version.to_string(), status, reason), headers);
        };
        let (version, status, reason) = resp_line;
        let mut resp = Response { status, reason, headers, body: Vec::new() };
        let conn_hdr = resp.header("connection").unwrap_or("").to_ascii_lowercase();
        let mut reusable = if version == "HTTP/1.0" { conn_hdr.contains("keep-alive") } else { !conn_hdr.contains("close") };

        let has_body = req.method != "HEAD" && status != 204 && status != 304 && !(100..200).contains(&status);
        if has_body {
            let to_sink = (200..300).contains(&status) && sink.is_some();
            let mut body = Vec::new();
            let mut sink = sink;
            let mut out = |d: &[u8]| -> io::Result<()> {
                if to_sink {
                    if let Some(s) = sink.as_mut() {
                        s.write_all(d)?;
                        progress(d.len() as u64);
                    }
                } else {
                    if body.len() + d.len() > 64 * 1024 * 1024 {
                        return Err(bad("response body too large"));
                    }
                    body.extend_from_slice(d);
                }
                Ok(())
            };
            let te = resp.header("transfer-encoding").unwrap_or("").to_ascii_lowercase();
            if te.contains("chunked") {
                loop {
                    let line = conn.read_line()?;
                    let size_str = line.split(';').next().unwrap_or("").trim();
                    let size = u64::from_str_radix(size_str, 16).map_err(|_| bad("bad chunk size"))?;
                    if size == 0 {
                        // trailers
                        while !conn.read_line()?.is_empty() {}
                        break;
                    }
                    conn.read_exact_to(size, &mut out)?;
                    if !conn.read_line()?.is_empty() {
                        return Err(bad("missing CRLF after chunk"));
                    }
                }
            } else if let Some(cl) = resp.header("content-length") {
                let n: u64 = cl.trim().parse().map_err(|_| bad("bad Content-Length"))?;
                conn.read_exact_to(n, &mut out)?;
            } else {
                conn.read_to_eof(&mut out)?;
                reusable = false;
            }
            resp.body = body;
        }
        if conn.pos != conn.len {
            reusable = false; // unexpected extra bytes
        }
        Ok((resp, reusable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn url_parse() {
        let u = Url::parse("https://s3.us-east-1.amazonaws.com").unwrap();
        assert_eq!((u.scheme.as_str(), u.host.as_str(), u.port, u.path.as_str()), ("https", "s3.us-east-1.amazonaws.com", 443, "/"));
        assert_eq!(u.host_header(), "s3.us-east-1.amazonaws.com");
        let u = Url::parse("http://127.0.0.1:9000/base/path?x=1#frag").unwrap();
        assert_eq!((u.port, u.path.as_str(), u.query.as_str()), (9000, "/base/path", "x=1"));
        assert_eq!(u.host_header(), "127.0.0.1:9000");
        assert!(u.is_ip_or_localhost());
        let u = Url::parse("http://[::1]:8333").unwrap();
        assert_eq!(u.host, "::1");
        assert_eq!(u.host_header(), "[::1]:8333");
        assert!(u.is_ip_or_localhost());
        let u = Url::parse("HTTPS://User@Example.COM:443/").unwrap();
        assert_eq!(u.host_header(), "example.com");
        assert!(!u.is_ip_or_localhost());
        assert!(Url::parse("ftp://x").is_err());
        assert!(Url::parse("example.com").is_err());
        assert!(Url::parse("http://h:99999").is_err());
    }

    /// One-shot fake server: reads one request then writes `reply`.
    fn serve(replies: Vec<Vec<u8>>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let mut reqs = Vec::new();
            let (mut s, _) = l.accept().unwrap();
            for r in replies {
                let mut buf = Vec::new();
                let mut b = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).unwrap() == 0 {
                        return reqs;
                    }
                    buf.push(b[0]);
                }
                let text = String::from_utf8_lossy(&buf).to_string();
                let cl = text
                    .lines()
                    .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap()))
                    .unwrap_or(0);
                let mut body = vec![0u8; cl];
                s.read_exact(&mut body).unwrap();
                reqs.push(text + &String::from_utf8_lossy(&body));
                s.write_all(&r).unwrap();
            }
            reqs
        });
        (port, h)
    }

    struct B(Vec<u8>);
    impl Body for B {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn open(&self) -> io::Result<Box<dyn Read + '_>> {
            Ok(Box::new(&self.0[..]))
        }
    }

    #[test]
    fn chunked_keepalive_and_sink() {
        let (port, h) = serve(vec![
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: y\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nETag: \"e\"\r\n\r\nabc".to_vec(),
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope".to_vec(),
        ]);
        let c = HttpClient::new(Arc::new(NoTls));
        let url = Url::parse(&format!("http://127.0.0.1:{}/a%20b?x=1", port)).unwrap();
        let r = c.send(&Request { method: "GET", url: &url, headers: &[], body: None, cancel: None }, None, &mut |_| {}).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello world");
        // second request reuses the same connection (server only accepts once)
        let body = B(b"payload".to_vec());
        let mut sink = Vec::new();
        let mut prog = 0;
        let r = c
            .send(&Request { method: "PUT", url: &url, headers: &[], body: Some(&body), cancel: None }, Some(&mut sink), &mut |n| prog += n)
            .unwrap();
        assert_eq!(r.header("etag"), Some("\"e\""));
        assert_eq!(sink, b"abc");
        assert_eq!(prog, 7 + 3);
        let mut sink2 = Vec::new();
        let r = c.send(&Request { method: "GET", url: &url, headers: &[], body: None, cancel: None }, Some(&mut sink2), &mut |_| {}).unwrap();
        assert_eq!((r.status, r.body.as_slice(), sink2.len()), (404, &b"nope"[..], 0));
        let reqs = h.join().unwrap();
        assert!(reqs[0].starts_with("GET /a%20b?x=1 HTTP/1.1\r\nHost: 127.0.0.1:"));
        assert!(reqs[1].contains("Content-Length: 7\r\n") && reqs[1].ends_with("payload"));
    }

    #[test]
    fn stale_connection_retried() {
        // Server answers one request on a connection then closes; the client
        // must transparently reconnect for the second request.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut s, _) = l.accept().unwrap();
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).unwrap();
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
                drop(s);
            }
        });
        let c = HttpClient::new(Arc::new(NoTls));
        let url = Url::parse(&format!("http://127.0.0.1:{}/", port)).unwrap();
        for _ in 0..2 {
            let r = c.send(&Request { method: "GET", url: &url, headers: &[], body: None, cancel: None }, None, &mut |_| {}).unwrap();
            assert_eq!(r.body, b"ok");
            std::thread::sleep(Duration::from_millis(50));
        }
        h.join().unwrap();
    }

    #[test]
    fn https_without_tls_errors() {
        let c = HttpClient::new(Arc::new(NoTls));
        let url = Url::parse("https://example.com/").unwrap();
        let e = c.send(&Request { method: "GET", url: &url, headers: &[], body: None, cancel: None }, None, &mut |_| {}).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }
}
