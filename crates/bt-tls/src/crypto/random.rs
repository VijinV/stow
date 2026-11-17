//! Operating-system cryptographic random number generator.
use std::io;

#[cfg(unix)]
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    if buf.is_empty() {
        return Ok(());
    }
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(buf)
}

#[cfg(windows)]
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(alg: *mut core::ffi::c_void, buf: *mut u8, len: u32, flags: u32) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x2;
    for chunk in buf.chunks_mut(u32::MAX as usize) {
        let st = unsafe {
            BCryptGenRandom(core::ptr::null_mut(), chunk.as_mut_ptr(), chunk.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
        };
        if st != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("BCryptGenRandom failed: {st:#x}")));
        }
    }
    Ok(())
}

pub fn array<const N: usize>() -> io::Result<[u8; N]> {
    let mut a = [0u8; N];
    fill(&mut a)?;
    Ok(a)
}

#[cfg(test)]
mod tests {
    #[test]
    fn not_all_zero() {
        let a = super::array::<32>().unwrap();
        let b = super::array::<32>().unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }
}
