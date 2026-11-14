//! Making a block device out of part of a file, which is how the bundles a
//! phone keeps its shared libraries in are opened.

#[cfg(target_os = "android")]
pub use android::*;

#[cfg(target_os = "android")]
mod android {
    use anyhow::{Context, Result};
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};

    const CONTROL: &str = "/dev/loop-control";

    const GET_FREE: u32 = 0x4C82;
    /// Bind a file to the device and then describe the part of it to read.
    /// Both go back to the oldest loop driver; `LOOP_CONFIGURE`, which does
    /// the two at once, arrived in Linux 5.8, and on the 4.19 kernels of the
    /// older phones it may answer as though it worked while the device reads
    /// nothing at all. Every kernel since accepts these two.
    const SET_FD: u32 = 0x4C00;
    const SET_STATUS64: u32 = 0x4C04;

    /// The device only ever reads. It stays pointed at the file until the
    /// recovery ends, which is as long as anything mounted from it lasts.
    const READ_ONLY: u32 = 1;

    /// Every field is a plain number or a run of bytes, so the request is
    /// made by zeroing it and filling in what matters.
    #[repr(C)]
    struct Info {
        device: u64,
        inode: u64,
        rdevice: u64,
        offset: u64,
        size_limit: u64,
        number: u32,
        encrypt_type: u32,
        encrypt_key_size: u32,
        flags: u32,
        file_name: [u8; 64],
        crypt_name: [u8; 64],
        encrypt_key: [u8; 32],
        init: [u64; 2],
    }

    /// Open `file` from `offset` for `length` bytes as a block device, and
    /// give its path. The device goes away once whatever is mounted from it
    /// is unmounted.
    pub fn attach(file: &Path, offset: u64, length: u64) -> Result<PathBuf> {
        let backing = File::open(file).with_context(|| format!("open {}", file.display()))?;
        let control = File::open(CONTROL).with_context(|| format!("open {CONTROL}"))?;
        let number = unsafe { libc::ioctl(control.as_raw_fd(), GET_FREE as libc::Ioctl) };
        if number < 0 {
            return Err(std::io::Error::last_os_error()).context("ask for a free loop device");
        }
        let path = free_device(number as u32)?;
        let device = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        // Bind the file first. Every loop driver answers this one; the single
        // ioctl that both binds and describes the device does not exist on
        // the older kernels and can leave one that reads back nothing.
        let fd = backing.as_raw_fd();
        if unsafe { libc::ioctl(device.as_raw_fd(), SET_FD as libc::Ioctl, fd) } < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("bind {} to {}", file.display(), path.display()));
        }
        let mut info: Info = unsafe { std::mem::zeroed() };
        info.offset = offset;
        info.size_limit = length;
        info.flags = READ_ONLY;
        if unsafe { libc::ioctl(device.as_raw_fd(), SET_STATUS64 as libc::Ioctl, &mut info) } < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("describe {} on {}", file.display(), path.display()));
        }
        Ok(path)
    }

    /// Where the kernel put the loop device it just handed out: Android
    /// keeps its block devices in their own directory.
    fn free_device(number: u32) -> Result<PathBuf> {
        for dir in ["/dev/block", "/dev"] {
            let path = Path::new(dir).join(format!("loop{number}"));
            if path.exists() {
                return Ok(path);
            }
        }
        anyhow::bail!("the kernel handed out loop device {number}, which is in neither /dev/block nor /dev")
    }
}
