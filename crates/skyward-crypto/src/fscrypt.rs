//! Letting a key into a filesystem, so the files it was used on can be
//! read. The kernel keeps the key for the filesystem, not for any one
//! file, and names it by a hash it works out itself, or, on the phones that
//! encrypt each user's files the older way, by a descriptor the phone chose
//! when it made the key.

use anyhow::{bail, Context, Result};
use std::path::Path;

/// How long the name the kernel gives a key is.
pub const NAME_BYTES: usize = 16;

/// How long the descriptor naming a key under the older kind of policy is.
pub const DESCRIPTOR_BYTES: usize = 8;

/// How a key is named: by the identifier the kernel works out from its
/// bytes, which is what the newer kind of policy uses, or by a descriptor
/// the phone chose, which is what the older kind uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Naming {
    Descriptor([u8; DESCRIPTOR_BYTES]),
    Identifier,
}

/// Let `raw` into the filesystem mounted at `mount`, and give the name the
/// kernel knows it by. Every file whose directory names that key can be
/// read from then on.
#[cfg(target_os = "android")]
pub fn add_key(mount: &Path, raw: &[u8], wrapped: bool) -> Result<[u8; NAME_BYTES]> {
    add_key_named(mount, raw, wrapped, Naming::Identifier)
}

/// Let `raw` into the filesystem mounted at `mount` under the name `naming`
/// gives it, and give the name the kernel knows it by.
#[cfg(target_os = "android")]
pub fn add_key_named(mount: &Path, raw: &[u8], wrapped: bool, naming: Naming) -> Result<[u8; NAME_BYTES]> {
    use std::os::fd::AsRawFd;
    /// The request's fixed part, before the key itself, on a kernel of a
    /// version before the one that added the flags after it.
    const HEADER_BYTES: usize = 80;
    const BY_DESCRIPTOR: u32 = 1;
    const BY_IDENTIFIER: u32 = 2;
    /// The key is one only the storage hardware can unwrap.
    const HARDWARE_WRAPPED: u32 = 1;
    const ADD_KEY: u32 = 0xc050_6617;

    let mut arg = vec![0u8; HEADER_BYTES + raw.len()];
    match naming {
        Naming::Descriptor(descriptor) => {
            arg[0..4].copy_from_slice(&BY_DESCRIPTOR.to_ne_bytes());
            arg[8..8 + DESCRIPTOR_BYTES].copy_from_slice(&descriptor);
        }
        Naming::Identifier => arg[0..4].copy_from_slice(&BY_IDENTIFIER.to_ne_bytes()),
    }
    arg[40..44].copy_from_slice(&(raw.len() as u32).to_ne_bytes());
    if wrapped {
        arg[76..80].copy_from_slice(&HARDWARE_WRAPPED.to_ne_bytes());
    }
    arg[HEADER_BYTES..].copy_from_slice(raw);
    let dir = std::fs::File::open(mount).with_context(|| format!("open {}", mount.display()))?;
    if unsafe { libc::ioctl(dir.as_raw_fd(), ADD_KEY as libc::Ioctl, arg.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("let a key into {}", mount.display()));
    }
    let mut name = [0u8; NAME_BYTES];
    name.copy_from_slice(&arg[8..8 + NAME_BYTES]);
    Ok(name)
}

/// How the phone's own table says the files under a mount point are
/// encrypted: the version of the policy, and the descriptor its keys are
/// named by under the older kind, which the table names itself.
///
/// The table is where the version comes from, and not the mounted
/// filesystem: a directory that is not encrypted under a policy of its own,
/// as `/data` itself is on a phone that encrypts each user's files only,
/// has none to read, and the keys for the directories below it are named by
/// what the table says regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Named {
    pub version: u8,
    pub descriptor: Option<[u8; DESCRIPTOR_BYTES]>,
}

impl Named {
    /// What `fileencryption=` says in the phone's own table, as
    /// `aes-256-xts:aes-256-cts:v1` or `::v1`.
    pub fn of_extra(said: &str) -> Result<Named> {
        // The version is the last part, and the parts after it are flags
        // joined on with a plus, as `::v2+inlinecrypt_optimized` writes them.
        let version = said
            .split(':')
            .find_map(|part| {
                let number = part.strip_prefix('v')?.split('+').next()?;
                number.parse::<u8>().ok()
            })
            .with_context(|| format!("{said} does not name a policy version"))?;
        // The table names the cipher and the modes, and not the descriptor:
        // a descriptor of nothing is what the kernel takes when the key is
        // to be named by one it works out itself.
        Ok(Named { version, descriptor: None })
    }

    /// How a key is named under this policy: by the descriptor the table
    /// named, where it named one, and otherwise by what the kernel works out
    /// from the key itself.
    pub fn naming(self) -> Naming {
        match self.descriptor {
            Some(d) => Naming::Descriptor(d),
            None => Naming::Identifier,
        }
    }
}

/// The way the files under `dir` are encrypted, as far as the kernel says:
/// the version of the policy, and the descriptor that names its key where
/// the policy is the older kind.
#[cfg(target_os = "android")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub version: u8,
    pub descriptor: Option<[u8; DESCRIPTOR_BYTES]>,
}

/// Read how `dir` is encrypted; `None` where it is not encrypted under any
/// policy of its own.
#[cfg(target_os = "android")]
pub fn policy_of(dir: &Path) -> Result<Option<Policy>> {
    use std::os::fd::AsRawFd;
    const GET_POLICY: u32 = 0xc009_6616;
    /// The largest policy there is: its version, three bytes of how it
    /// encrypts, four reserved, and the key's name.
    const POLICY_BYTES: usize = 24;

    let folder = std::fs::File::open(dir).with_context(|| format!("open {}", dir.display()))?;
    let mut raw = [0u8; 8 + POLICY_BYTES];
    raw[..8].copy_from_slice(&(POLICY_BYTES as u64).to_ne_bytes());
    if unsafe { libc::ioctl(folder.as_raw_fd(), GET_POLICY as libc::Ioctl, raw.as_mut_ptr()) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODATA) {
            return Ok(None);
        }
        return Err(e).with_context(|| format!("read how {} is encrypted", dir.display()));
    }
    let body = &raw[8..];
    let version = body[0];
    let descriptor = match version {
        0 => {
            let mut d = [0u8; DESCRIPTOR_BYTES];
            d.copy_from_slice(&body[4..4 + DESCRIPTOR_BYTES]);
            Some(d)
        }
        _ => None,
    };
    Ok(Some(Policy { version, descriptor }))
}

/// Whether the names and contents under `dir` read as they are: it is not
/// encrypted, or the key it is encrypted with is in the kernel. A user's
/// own files read only once that user's key is let in.
#[cfg(target_os = "android")]
pub fn unlocked(dir: &Path) -> Result<bool> {
    use std::os::fd::AsRawFd;
    const GET_POLICY: u32 = 0xc009_6616;
    const GET_KEY_STATUS: u32 = 0xc080_661a;
    /// How the first kind of policy names its key, and how the second does.
    const BY_DESCRIPTOR: u32 = 1;
    const BY_IDENTIFIER: u32 = 2;
    /// The second kind of policy is the largest: its version, three bytes
    /// of how it encrypts, four reserved, and the key's name.
    const POLICY_BYTES: usize = 24;
    const PRESENT: u32 = 2;

    let Some(policy) = policy_of(dir)? else { return Ok(true) };
    let folder = std::fs::File::open(dir).with_context(|| format!("open {}", dir.display()))?;
    let mut raw = [0u8; 8 + POLICY_BYTES];
    raw[..8].copy_from_slice(&(POLICY_BYTES as u64).to_ne_bytes());
    if unsafe { libc::ioctl(folder.as_raw_fd(), GET_POLICY as libc::Ioctl, raw.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("read how {} is encrypted", dir.display()));
    }
    let body = &raw[8..];
    let mut status = [0u8; 128];
    match policy.version {
        0 => {
            status[..4].copy_from_slice(&BY_DESCRIPTOR.to_ne_bytes());
            status[8..16].copy_from_slice(&body[4..12]);
        }
        2 => {
            status[..4].copy_from_slice(&BY_IDENTIFIER.to_ne_bytes());
            status[8..8 + NAME_BYTES].copy_from_slice(&body[8..8 + NAME_BYTES]);
        }
        other => bail!("{} is encrypted under a policy of version {other}, which is not known here", dir.display()),
    }
    if unsafe { libc::ioctl(folder.as_raw_fd(), GET_KEY_STATUS as libc::Ioctl, status.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("ask whether the key for {} is in", dir.display()));
    }
    Ok(u32::from_ne_bytes(status[64..68].try_into().expect("four bytes")) == PRESENT)
}

/// Whether what a phone says about how it encrypts its files means the
/// keys are ones only the storage hardware can unwrap.
pub fn hardware_wrapped(mode: &str) -> bool {
    mode.split(['+', ':']).any(|part| part == "wrappedkey_v0")
}

/// Read the name the phone recorded for a key it let in, to check against
/// the name the kernel works out now.
pub fn recorded_name(path: &Path) -> Result<[u8; NAME_BYTES]> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    match <[u8; NAME_BYTES]>::try_from(&raw[..]) {
        Ok(name) => Ok(name),
        Err(_) => bail!("{} holds {} bytes, and a key's name is {NAME_BYTES}", path.display(), raw.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The version of the policy is the phone's table's to say, as
    /// `fileencryption=::v1` or `aes-256-xts:aes-256-cts:v2`.
    #[test]
    fn the_table_says_which_version_of_policy_it_uses() {
        assert_eq!(Named::of_extra("::v1").unwrap(), Named { version: 1, descriptor: None });
        assert_eq!(Named::of_extra("aes-256-xts:aes-256-cts:v2").unwrap().version, 2);
        assert_eq!(Named::of_extra("aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized").unwrap().version, 2);
        assert!(Named::of_extra("aes-256-xts").is_err(), "no version named");
        // No table names a descriptor, so the kernel works the name out.
        assert_eq!(Named::of_extra("::v1").unwrap().naming(), Naming::Identifier);
    }

    /// The descriptor the older kind of policy names a key by is the eight
    /// bytes the phone chose, taken as they lie.
    #[test]
    fn the_older_kind_of_policy_names_its_key_by_its_descriptor() {
        assert_eq!(DESCRIPTOR_BYTES, 8);
        let descriptor = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(Naming::Descriptor(descriptor), Naming::Descriptor(descriptor));
        assert_ne!(Naming::Descriptor(descriptor), Naming::Identifier);
    }

    #[test]
    fn a_phone_says_whether_the_hardware_holds_the_keys() {
        assert!(hardware_wrapped("aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0"));
        assert!(!hardware_wrapped("aes-256-xts:aes-256-cts:v2"));
        assert!(!hardware_wrapped("aes-256-xts:aes-256-cts:v2+wrappedkey_v1"));
    }

    #[test]
    fn a_name_is_read_back_only_at_its_own_length() {
        let dir = std::env::temp_dir().join(format!("skyward-fscrypt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("ref");
        std::fs::write(&good, [7u8; NAME_BYTES]).unwrap();
        assert_eq!(recorded_name(&good).unwrap(), [7u8; NAME_BYTES]);
        let short = dir.join("short");
        std::fs::write(&short, [7u8; 8]).unwrap();
        assert!(recorded_name(&short).is_err());
    }
}
