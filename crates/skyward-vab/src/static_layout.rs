//! The partitions of a phone that keeps them of its own.
//!
//! The phones Skyward was built for put their system, vendor and the rest
//! in `super` as logical partitions of a slot; the older OPPO phones keep
//! each of them on a partition of its own, with the names their own table
//! gives them. What the recovery reads from super's metadata there is read
//! here from that table, and the partitions are mounted where the
//! recovery's programs and pages look for them, so that everything past
//! this module works the same on either kind of phone.

use crate::{Mounted, Mounts, Slot, Whole};
use anyhow::{Context, Result};
use skyward_block::{mount, BY_NAME};
use std::fs;
use std::path::{Path, PathBuf};

/// The tables a recovery keeps of the phone's own partitions, read in this
/// order.
const TABLES: [&str; 2] = ["/system/etc/recovery.fstab", "/etc/recovery.fstab"];

/// The partitions that hold the system beside the recovery: what a phone
/// with dynamic partitions keeps in super, and what is mounted here for the
/// recovery's programs and its pages to read. In this order, which is the
/// order init reads the installed system's properties in.
const SYSTEM: [&str; 6] = ["system", "system_ext", "vendor", "product", "odm", "vendor_dlkm"];

/// One partition of the phone's own table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The name the recovery works with, without a slot: `system`.
    pub base: String,
    /// The partition the phone keeps it on: `system`, or `oem` for the
    /// vendor partition of the older OPPO phones.
    pub partition: String,
    /// Where the phone's own table mounts it.
    pub mount_point: String,
    /// The path the table gives the partition, which the phone's own
    /// recovery uses. It is the one to read through where it is there, so a
    /// phone whose partitions are reached another way keeps working.
    pub device_path: String,
}

impl Entry {
    /// The block device the partition is: the path the phone's own table
    /// gives it, or else the one its name reaches it by.
    pub fn device(&self) -> PathBuf {
        let named = Path::new(&self.device_path);
        if named.exists() {
            return named.to_path_buf();
        }
        Path::new(BY_NAME).join(&self.partition)
    }

    /// Where the recovery mounts it: the recovery's own /system stays, so
    /// the installed one goes under /mnt.
    pub fn recovery_mount_point(&self) -> PathBuf {
        crate::mount_point(&self.base)
    }

    /// The name the recovery knows it by, with the one slot it has.
    pub fn recovery_name(&self) -> String {
        format!("{}{}", self.base, Slot::A.suffix())
    }
}

/// The phone's own table, as the partitions that belong to the system.
pub fn entries() -> Result<Vec<Entry>> {
    let mut out: Vec<Entry> = Vec::new();
    for table in TABLES {
        let text = match fs::read_to_string(table) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("read {table}")),
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [device, point, ..] = fields[..] else { continue };
            let base = point.trim_start_matches('/');
            if !SYSTEM.contains(&base) || out.iter().any(|e| e.base == base) {
                continue;
            }
            let Some(partition) = Path::new(device).file_name().and_then(|n| n.to_str()) else { continue };
            out.push(Entry {
                base: base.to_string(),
                partition: partition.to_string(),
                mount_point: point.to_string(),
                device_path: device.to_string(),
            });
        }
        if !out.is_empty() {
            break;
        }
    }
    out.sort_by_key(|e| SYSTEM.iter().position(|b| *b == e.base).unwrap_or(SYSTEM.len()));
    Ok(out)
}

/// One of the phone's partitions, mounted read-only where the recovery
/// looks for it.
pub fn mount_one(entry: &Entry) -> Result<Mounted> {
    let (at, device) = (entry.recovery_mount_point(), entry.device());
    let filesystem = if mount::is_mount_point(&at)? {
        // The recovery's own init may have mounted it already, or an
        // earlier run of the recovery may have left it.
        mount::visible(&at)?.map(|v| v.filesystem).unwrap_or_else(|| "unknown".to_string())
    } else {
        fs::create_dir_all(&at).with_context(|| format!("create {}", at.display()))?;
        // Over whatever shows there, as the recovery's init may have
        // mounted the phone's own partitions in the folders below it.
        mount::mount_ro_over(&device, &at).with_context(|| format!("mount {} on {}", entry.partition, at.display()))?.to_string()
    };
    Ok(Mounted { partition: entry.recovery_name(), device, mount_point: at, filesystem })
}

/// Mount the phone's partitions read-only, in the order of the table. One
/// that does not mount is left out with the reason said, as a phone whose
/// super cannot be read still comes up: the recovery stays usable without
/// it, and what is mounted is what the pages work with.
pub fn mount_partitions() -> Result<Mounts> {
    let mut mounts = Mounts::default();
    for entry in entries()? {
        match mount_one(&entry) {
            Ok(mounted) => mounts.partitions.push(mounted),
            Err(e) => {
                mounts.damaged.push(format!("{}: {e:#}", entry.base));
                eprintln!("{} not mounted: {e:#}", entry.base);
            }
        }
    }
    Ok(mounts)
}

/// One of the phone's partitions by the name the recovery knows it by.
pub fn entry(base: &str) -> Result<Entry> {
    entries()?.into_iter().find(|e| e.base == base).with_context(|| format!("the phone's table holds no {base} partition"))
}

/// Mount one of the phone's partitions by base name, as [`mount_one`].
pub fn mount_base(base: &str) -> Result<Mounted> {
    mount_one(&entry(base)?)
}

/// Unmount one of the phone's partitions by base name, where its own device
/// is what shows there; one the recovery's init mounted is taken as it is.
pub fn unmount_base(base: &str) -> Result<()> {
    let entry = entry(base)?;
    let at = entry.recovery_mount_point();
    if let Some(shown) = mount::visible(&at)?
        && shown.device == skyward_block::devnum(entry.device())?
    {
        mount::umount(&at).with_context(|| format!("unmount {}", at.display()))?;
    }
    Ok(())
}

/// The phone's partitions that are mounted where the recovery looks for
/// them, in the order of the table.
pub fn mounted_partitions() -> Result<Vec<Mounted>> {
    let mut found = Vec::new();
    for entry in entries()? {
        let at = entry.recovery_mount_point();
        let Some(shown) = mount::visible(&at)? else { continue };
        if shown.device != skyward_block::devnum(entry.device())? {
            continue;
        }
        found.push(Mounted {
            partition: entry.recovery_name(),
            device: entry.device(),
            mount_point: at,
            filesystem: shown.filesystem,
        });
    }
    Ok(found)
}

/// The base names of the phone's partitions, in the order of the table.
pub fn bases() -> Result<Vec<String>> {
    Ok(entries()?.into_iter().map(|e| e.base).collect())
}

/// The phone's partitions by base name with the bytes each holds.
pub fn sizes() -> Result<Vec<(String, u64)>> {
    let mut out = Vec::new();
    for entry in entries()? {
        let size = skyward_block::size_bytes(entry.device()).unwrap_or(0);
        out.push((entry.base, size));
    }
    Ok(out)
}

/// One of the phone's partitions whole, for a backup to read it or a
/// restore to write it: the partition itself, with no mapping over it.
pub fn whole(base: &str, name: &str) -> Result<Whole> {
    let entry = entry(base)?;
    let device = entry.device();
    let size = skyward_block::size_bytes(&device)?;
    Ok(Whole { name: name.to_string(), device, size })
}

/// Unmount the phone's partitions before an update writes over them; a
/// partition whose mount point is in `busy` still has files in use, so it
/// only leaves the tree.
pub fn release(busy: &[PathBuf]) -> Result<()> {
    for mounted in mounted_partitions()?.into_iter().rev() {
        if busy.contains(&mounted.mount_point) {
            mount::umount_detach(&mounted.mount_point).with_context(|| format!("detach {}", mounted.mount_point.display()))?;
        } else {
            mount::umount(&mounted.mount_point).with_context(|| format!("unmount {}", mounted.mount_point.display()))?;
        }
    }
    Ok(())
}

/// Unmount every one of the phone's partitions, in the reverse order of the
/// table.
pub fn unmount_partitions() -> Result<()> {
    for base in bases()?.into_iter().rev() {
        unmount_base(&base)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_partitions_are_read_from_a_recovery_table() {
        let table = "\
/dev/block/bootdevice/by-name/boot\t/boot\temmc\tdefaults\tdefaults
/dev/block/platform/soc/7824900.sdhci/by-name/system\t/system\text4\tro\twait
/dev/block/platform/soc/7824900.sdhci/by-name/oem\t/vendor\tsquashfs\tro\twait
/dev/block/bootdevice/by-name/userdata\t/data\tf2fs\tnosuid\twait
";
        let mut out: Vec<Entry> = Vec::new();
        for line in table.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [device, point, ..] = fields[..] else { continue };
            let base = point.trim_start_matches('/');
            if !SYSTEM.contains(&base) {
                continue;
            }
            let partition = Path::new(device).file_name().unwrap().to_str().unwrap().to_string();
            out.push(Entry { base: base.to_string(), partition, mount_point: point.to_string(), device_path: device.to_string() });
        }
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].base, "system");
        assert_eq!(out[1].base, "vendor");
        assert_eq!(out[1].partition, "oem", "the vendor partition is the phone's own oem one");
        assert_eq!(out[1].partition, "oem");
        assert_eq!(out[1].device_path, "/dev/block/platform/soc/7824900.sdhci/by-name/oem");
        assert_eq!(out[1].recovery_name(), "vendor_a");
    }
}
