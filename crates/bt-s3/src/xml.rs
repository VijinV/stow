//! Tiny non-validating XML parser, sufficient for S3 API responses.

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Element>,
    /// Concatenated character data directly inside this element.
    pub text: String,
}

impl Element {
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.as_str())
    }
}

/// Escape text for inclusion in XML content or attribute values.
pub fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c => o.push(c),
        }
    }
    o
}

/// Decode the five predefined entities and numeric character references.
pub fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut o = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        o.push_str(&rest[..i]);
        rest = &rest[i..];
        let end = match rest.find(';') {
            Some(e) if e <= 12 => e,
            _ => {
                o.push('&');
                rest = &rest[1..];
                continue;
            }
        };
        let ent = &rest[1..end];
        let rep = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32)
            }
            _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match rep {
            Some(c) => {
                o.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                o.push('&');
                rest = &rest[1..];
            }
        }
    }
    o.push_str(rest);
    o
}

fn local_name(n: &str) -> &str {
    n.rsplit(':').next().unwrap_or(n)
}

/// Parse a document and return its root element. Namespace prefixes are stripped.
pub fn parse(input: &str) -> Result<Element, String> {
    let b = input.as_bytes();
    let mut i = 0;
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    while i < b.len() {
        if b[i] == b'<' {
            if input[i..].starts_with("<?") {
                i = input[i..].find("?>").map(|e| i + e + 2).ok_or("unterminated <?")?;
            } else if input[i..].starts_with("<!--") {
                i = input[i..].find("-->").map(|e| i + e + 3).ok_or("unterminated comment")?;
            } else if input[i..].starts_with("<![CDATA[") {
                let e = input[i..].find("]]>").ok_or("unterminated CDATA")?;
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&input[i + 9..i + e]);
                }
                i += e + 3;
            } else if input[i..].starts_with("<!") {
                i = input[i..].find('>').map(|e| i + e + 1).ok_or("unterminated <!")?;
            } else if input[i..].starts_with("</") {
                let e = input[i..].find('>').ok_or("unterminated end tag")?;
                let name = local_name(input[i + 2..i + e].trim());
                let el = stack.pop().ok_or("unexpected end tag")?;
                if el.name != name {
                    return Err(format!("mismatched end tag </{}> for <{}>", name, el.name));
                }
                match stack.last_mut() {
                    Some(p) => p.children.push(el),
                    None => root = Some(el),
                }
                i += e + 1;
            } else {
                // start tag; find '>' outside quotes
                let mut j = i + 1;
                let mut q: u8 = 0;
                while j < b.len() {
                    let c = b[j];
                    if q != 0 {
                        if c == q {
                            q = 0;
                        }
                    } else if c == b'"' || c == b'\'' {
                        q = c;
                    } else if c == b'>' {
                        break;
                    }
                    j += 1;
                }
                if j >= b.len() {
                    return Err("unterminated start tag".into());
                }
                let mut inner = &input[i + 1..j];
                let self_close = inner.ends_with('/');
                if self_close {
                    inner = &inner[..inner.len() - 1];
                }
                let name_end = inner.find(|c: char| c.is_whitespace()).unwrap_or(inner.len());
                let mut el = Element { name: local_name(&inner[..name_end]).to_string(), ..Default::default() };
                el.attrs = parse_attrs(&inner[name_end..]);
                if self_close {
                    match stack.last_mut() {
                        Some(p) => p.children.push(el),
                        None => root = Some(el),
                    }
                } else {
                    stack.push(el);
                }
                i = j + 1;
            }
        } else {
            let e = input[i..].find('<').map(|e| i + e).unwrap_or(b.len());
            if let Some(top) = stack.last_mut() {
                top.text.push_str(&unescape(&input[i..e]));
            }
            i = e;
        }
    }
    if !stack.is_empty() {
        return Err("unexpected end of document".into());
    }
    root.ok_or_else(|| "empty document".into())
}

fn parse_attrs(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = s.trim();
    while let Some(eq) = rest.find('=') {
        let name = rest[..eq].trim().to_string();
        let after = rest[eq + 1..].trim_start();
        let Some(q) = after.chars().next() else { break };
        if q != '"' && q != '\'' {
            break;
        }
        let Some(end) = after[1..].find(q) else { break };
        out.push((local_name(&name).to_string(), unescape(&after[1..1 + end])));
        rest = after[end + 2..].trim_start();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_list() {
        let doc = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><IsTruncated>true</IsTruncated>
<Contents><Key>a &amp; b/caf&#233; &#x1F600;.txt</Key><ETag>&quot;abc&quot;</ETag><Size>12</Size></Contents>
<Contents><Key><![CDATA[x<y]]></Key><Size>0</Size></Contents><Empty/><!-- c --></ListBucketResult>"#;
        let r = parse(doc).unwrap();
        assert_eq!(r.name, "ListBucketResult");
        assert_eq!(r.attrs[0].1, "http://s3.amazonaws.com/doc/2006-03-01/");
        let c: Vec<_> = r.children_named("Contents").collect();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].child_text("Key"), Some("a & b/café 😀.txt"));
        assert_eq!(c[0].child_text("ETag"), Some("\"abc\""));
        assert_eq!(c[1].child_text("Key"), Some("x<y"));
        assert!(r.child("Empty").is_some());
        assert!(parse("<a><b></a>").is_err());
        assert_eq!(escape("<a&'\">"), "&lt;a&amp;&apos;&quot;&gt;");
        assert_eq!(unescape("a&bogus;b&amp"), "a&bogus;b&amp");
    }
}
