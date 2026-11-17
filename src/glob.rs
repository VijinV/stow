//! Tiny glob matcher for exclude rules: `*`, `?`, `**`, `[abc]`, `[!a-z]`.
//! A pattern without `/` matches any single path component (e.g. `node_modules`, `*.tmp`);
//! a pattern with `/` matches the whole relative path (e.g. `build/**`, `**/cache/*`).

pub fn matches(pattern: &str, rel_path: &str) -> bool {
    let pattern = pattern.trim().trim_start_matches("./");
    if pattern.is_empty() {
        return false;
    }
    let pattern = pattern.trim_end_matches('/');
    if pattern.contains('/') {
        let p = pattern.trim_start_matches('/');
        glob(p.as_bytes(), rel_path.as_bytes(), true)
    } else {
        rel_path.split('/').any(|c| glob(pattern.as_bytes(), c.as_bytes(), false))
    }
}

fn class(p: &[u8], c: u8) -> Option<(bool, usize)> {
    // returns (matched, bytes consumed incl. brackets)
    let mut i = 1;
    let neg = matches!(p.get(1), Some(b'!') | Some(b'^'));
    if neg {
        i += 1;
    }
    let mut hit = false;
    let start = i;
    while i < p.len() && (p[i] != b']' || i == start) {
        if i + 2 < p.len() && p[i + 1] == b'-' && p[i + 2] != b']' {
            if p[i] <= c && c <= p[i + 2] {
                hit = true;
            }
            i += 3;
        } else {
            if p[i] == c {
                hit = true;
            }
            i += 1;
        }
    }
    if i >= p.len() {
        return None;
    }
    Some((hit != neg, i + 1))
}

fn glob(p: &[u8], s: &[u8], path_mode: bool) -> bool {
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize, bool)> = None; // (pattern idx after star, s idx, is_double)
    while si < s.len() {
        if pi < p.len() {
            match p[pi] {
                b'*' => {
                    let double = path_mode && p.get(pi + 1) == Some(&b'*');
                    let mut np = pi + if double { 2 } else { 1 };
                    if double && p.get(np) == Some(&b'/') {
                        // "**/" may match zero directories
                        if glob(&p[np + 1..], &s[si..], path_mode) {
                            return true;
                        }
                        np += 1;
                    }
                    star = Some((np, si, double));
                    pi = np;
                    continue;
                }
                b'?' if !(path_mode && s[si] == b'/') => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                b'[' => {
                    if let Some((ok, n)) = class(&p[pi..], s[si]) {
                        if ok && !(path_mode && s[si] == b'/') {
                            pi += n;
                            si += 1;
                            continue;
                        }
                    } else if s[si] == b'[' {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                }
                c if c == s[si] => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }
        // mismatch: backtrack to last star
        match star {
            Some((np, ss, double)) => {
                if !double && path_mode && s[ss] == b'/' {
                    return false;
                }
                star = Some((np, ss + 1, double));
                pi = np;
                si = ss + 1;
            }
            None => return false,
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::matches;
    #[test]
    fn basics() {
        assert!(matches("*.tmp", "a/b/c.tmp"));
        assert!(!matches("*.tmp", "a/b/c.tmpx"));
        assert!(matches("node_modules", "proj/node_modules/x/y.js"));
        assert!(matches(".DS_Store", ".DS_Store"));
        assert!(matches("Thumbs.db", "pics/Thumbs.db"));
        assert!(matches("build/**", "build/a/b.o"));
        assert!(!matches("build/**", "src/build/a.o"));
        assert!(matches("**/cache/*", "a/b/cache/x"));
        assert!(matches("**/cache/*", "cache/x"));
        assert!(!matches("**/cache/*", "cache/x/y"));
        assert!(matches("file?.txt", "dir/file1.txt"));
        assert!(matches("[ab]*.log", "x/a1.log"));
        assert!(!matches("[!ab]*.log", "x/a1.log"));
        assert!(matches("~$*", "docs/~$report.docx"));
        assert!(!matches("", "a"));
    }
}
