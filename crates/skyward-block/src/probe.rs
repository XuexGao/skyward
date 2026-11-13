//! What a partition holds now: the filesystem on it, which need not be the
//! one the phone's own table names for it. blkid names the filesystems it
//! knows; erofs, which the ramdisk's blkid does not know, is read by the
//! erofs tools the ramdisk carries, and squashfs, which the older phones
//! keep their vendor partition as, by its own magic.

use crate::tools;
use anyhow::Result;
use std::path::Path;

/// blkid is one of the commands in the ramdisk's box of them, which takes
/// the name of the one to run.
const BOX: &str = "toybox";
const BLKID: &str = "blkid";

/// What reads an erofs superblock, ending well only on one.
const DUMP_EROFS: &str = "dump.erofs";
const EROFS: &str = "erofs";

/// The magic a squashfs superblock starts with, and the filesystem's name.
const SQUASHFS_MAGIC: [u8; 4] = *b"hsqs";
const SQUASHFS: &str = "squashfs";

/// The filesystem on `device`; none where it holds nothing known, which is
/// how a partition reads after it has been discarded.
pub fn filesystem(device: &Path) -> Result<Option<String>> {
    let path = tools::path(device)?;
    let ran = tools::find(BOX)?.run(&[BLKID.to_string(), path.clone()])?;
    if let Some(named) = named(&ran.said) {
        return Ok(Some(named));
    }
    let erofs = tools::find(DUMP_EROFS)?.run(&[path])?;
    if erofs.status == 0 {
        return Ok(Some(EROFS.to_string()));
    }
    Ok(superblock(device)?.filter(|fs| fs == SQUASHFS))
}

/// The filesystem the first bytes of `device` name, where they name one
/// blkid does not know: squashfs's magic at the start of its superblock.
fn superblock(device: &Path) -> Result<Option<String>> {
    use anyhow::Context;
    use std::io::Read;
    let mut file = match std::fs::File::open(device) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read the superblock of {}", device.display())),
    };
    let mut magic = [0u8; 4];
    match file.read_exact(&mut magic) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read the superblock of {}", device.display())),
    }
    Ok((magic == SQUASHFS_MAGIC).then(|| SQUASHFS.to_string()))
}

/// The filesystem blkid names in a line such as
/// `/dev/block/dm-8: LABEL="data" UUID="…" TYPE="f2fs"`.
fn named(said: &str) -> Option<String> {
    said.split_whitespace().find_map(|field| {
        let value = field.strip_prefix("TYPE=")?.trim_matches('"');
        (!value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filesystem_is_read_off_the_line_blkid_prints() {
        assert_eq!(named("/dev/block/dm-8: TYPE=\"f2fs\"\n").as_deref(), Some("f2fs"));
        assert_eq!(named("/dev/block/dm-9: LABEL=\"metadata\" UUID=\"2d0f\" TYPE=\"ext4\"").as_deref(), Some("ext4"));
    }

    #[test]
    fn a_squashfs_superblock_is_read_by_its_own_magic() {
        let dir = std::env::temp_dir().join(format!("skyward-probe-squashfs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oem.img");
        std::fs::write(&path, b"hsqs\x00\x00\x00\x00rest").unwrap();
        assert_eq!(superblock(&path).unwrap().as_deref(), Some("squashfs"));
        std::fs::write(&path, b"\x53\xef").unwrap();
        assert_eq!(superblock(&path).unwrap(), None, "a device too short to hold a superblock");
        assert_eq!(superblock(&dir.join("gone")).unwrap(), None, "a device that is not there");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_partition_blkid_makes_nothing_of_holds_no_filesystem_it_knows() {
        assert_eq!(named(""), None, "a partition it says nothing about");
        assert_eq!(named("/dev/block/dm-8: PTTYPE=\"dos\""), None, "a partition table is not a filesystem");
    }
}
