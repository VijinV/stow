//! Build script: on Windows targets, embed the app icon + manifest into the .exe.
//! The .res file is generated here byte-by-byte (no resource compiler needed for MSVC);
//! for the GNU toolchain it is converted to an object with windres when available.
use std::path::PathBuf;

fn push_res(out: &mut Vec<u8>, rtype: u16, name: u16, lang: u16, data: &[u8]) {
    let mut hdr = Vec::new();
    hdr.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataSize
    hdr.extend_from_slice(&32u32.to_le_bytes()); // HeaderSize
    hdr.extend_from_slice(&0xFFFFu16.to_le_bytes());
    hdr.extend_from_slice(&rtype.to_le_bytes());
    hdr.extend_from_slice(&0xFFFFu16.to_le_bytes());
    hdr.extend_from_slice(&name.to_le_bytes());
    hdr.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
    hdr.extend_from_slice(&0x1030u16.to_le_bytes()); // MOVEABLE|PURE|DISCARDABLE
    hdr.extend_from_slice(&lang.to_le_bytes());
    hdr.extend_from_slice(&0u32.to_le_bytes()); // Version
    hdr.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    out.extend_from_slice(&hdr);
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn build_res(ico: &[u8], manifest: &str) -> Vec<u8> {
    let mut res = Vec::new();
    push_res(&mut res, 0, 0, 0, &[]); // mandatory empty first entry (32-bit .res marker)
    // ICONDIR: reserved, type, count; then 16-byte entries.
    let count = u16::from_le_bytes([ico[4], ico[5]]) as usize;
    let mut group = vec![0u8, 0, 1, 0];
    group.extend_from_slice(&(count as u16).to_le_bytes());
    for i in 0..count {
        let e = &ico[6 + i * 16..6 + (i + 1) * 16];
        let size = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as usize;
        let off = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as usize;
        let id = (i + 1) as u16;
        push_res(&mut res, 3, id, 0x0409, &ico[off..off + size]); // RT_ICON
        group.extend_from_slice(&e[0..12]); // w,h,colors,reserved,planes,bitcount,bytes
        group.extend_from_slice(&id.to_le_bytes());
    }
    push_res(&mut res, 14, 1, 0x0409, &group); // RT_GROUP_ICON
    push_res(&mut res, 24, 1, 0x0409, manifest.as_bytes()); // RT_MANIFEST, CREATEPROCESS_MANIFEST_RESOURCE_ID
    res
}

const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Stow" version="0.2.1.0"/>
  <description>Stow</description>
  <dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/></dependentAssembly></dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <activeCodePage xmlns="http://schemas.microsoft.com/SMI/2019/WindowsSettings">UTF-8</activeCodePage>
    </windowsSettings>
  </application>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo>
</assembly>
"#;

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let ico = match std::fs::read("assets/icon.ico") {
        Ok(i) => i,
        Err(_) => return,
    };
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let res_path = out_dir.join("app.res");
    std::fs::write(&res_path, build_res(&ico, MANIFEST)).unwrap();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if env == "msvc" {
        println!("cargo:rustc-link-arg-bins={}", res_path.display());
    } else {
        // GNU: convert .res -> COFF object with windres if present.
        let obj = out_dir.join("app_res.o");
        for tool in ["x86_64-w64-mingw32-windres", "windres"] {
            let ok = std::process::Command::new(tool)
                .args(["--input-format=res", "--output-format=coff", "-i"])
                .arg(&res_path)
                .arg("-o")
                .arg(&obj)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                println!("cargo:rustc-link-arg-bins={}", obj.display());
                return;
            }
        }
        println!("cargo:warning=windres not found: building without embedded icon/manifest");
    }
}
