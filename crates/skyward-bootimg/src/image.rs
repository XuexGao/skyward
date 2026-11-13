use abootimg_oxide::{binrw::io::Cursor, Header, HeaderV0Versioned, HeaderV3};
use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::Path;

/// The page size of a version 3 or 4 header, which keeps none of its own.
const V3_PAGE: usize = 4096;

/// The most that may follow a boot image's sections and still be kept: the
/// signature patch OPPO's bootloader wants after the image on these phones
/// is 1280 bytes, and a whole partition's padding is megabytes. What is
/// longer is a partition, not a patch.
const TRAILER_MAX: usize = 8 << 10;

/// A boot image with header version 0 through 4: its header, the sections
/// after it, and whatever follows them.
///
/// Versions 0 to 2 carry a second stage bootloader, a recovery DTBO (1 and
/// 2) and a device tree (2), and their page size is their header's. The
/// images OPPO's phones boot are these, and their bootloader reads a
/// signature patch appended after the last section, which travels on in
/// [`BootImage::trailer`]. Versions 3 and 4 carry only a kernel and a
/// ramdisk, and their partition's padding and footer are laid out again
/// when the image is packed.
pub struct BootImage {
    pub header: Header,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    /// The second stage bootloader (versions 0 to 2); empty when the image
    /// has none.
    pub second: Vec<u8>,
    /// The recovery DTBO/ACPIO (versions 1 and 2); empty when the image has
    /// none.
    pub dtbo: Vec<u8>,
    /// The device tree (version 2); empty when the image has none.
    pub dtb: Vec<u8>,
    /// What follows the sections, byte for byte, as on the stock OPPO
    /// images whose bootloader wants its signature patch there. Empty on
    /// the modern images, which end at their last section.
    pub trailer: Vec<u8>,
}

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    let end = at + len as usize;
    bytes.get(at..end).map(<[u8]>::to_vec).ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

/// What may follow a boot image's sections: the OPPO signature patch, with
/// the partition's padding after it taken off. Anything longer than a patch
/// is the partition itself, and the packer lays that out again.
fn trailer(rest: &[u8]) -> Vec<u8> {
    let kept = match rest.iter().rposition(|b| *b != 0) {
        Some(last) => &rest[..=last],
        None => &[],
    };
    if kept.len() > TRAILER_MAX {
        Vec::new()
    } else {
        kept.to_vec()
    }
}

impl BootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        BootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    /// The image `bytes` hold, as a partition holds it: the image, then
    /// whatever fills the partition after it.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = Header::parse(&mut Cursor::new(bytes)).context("header")?;
        let image = match &header {
            Header::V0(h) => {
                anyhow::ensure!(h.page_size != 0, "the header names no page size");
                let (dtbo, dtb) = match h.versioned {
                    HeaderV0Versioned::V0 => (Vec::new(), Vec::new()),
                    HeaderV0Versioned::V1 { recovery_dtbo_size, .. } => (section(bytes, h.recovery_dtbo_position(), recovery_dtbo_size, "recovery DTBO")?, Vec::new()),
                    HeaderV0Versioned::V2 { recovery_dtbo_size, dtb_size, .. } => (
                        section(bytes, h.recovery_dtbo_position(), recovery_dtbo_size, "recovery DTBO")?,
                        section(bytes, h.dtb_position().expect("a version 2 header names the device tree's position"), dtb_size, "device tree")?,
                    ),
                };
                BootImage {
                    header: header.clone(),
                    kernel: section(bytes, h.kernel_position(), h.kernel_size, "kernel")?,
                    ramdisk: section(bytes, h.ramdisk_position(), h.ramdisk_size, "ramdisk")?,
                    second: section(bytes, h.second_bootloader_position(), h.second_bootloader_size, "second stage bootloader")?,
                    dtbo,
                    dtb,
                    trailer: trailer(bytes.get(h.boot_image_size()..).unwrap_or_default()),
                }
            }
            Header::V3(h) => BootImage {
                header: header.clone(),
                kernel: section(bytes, HeaderV3::kernel_position(), h.kernel_size, "kernel")?,
                ramdisk: section(bytes, h.ramdisk_position(), h.ramdisk_size, "ramdisk")?,
                second: Vec::new(),
                dtbo: Vec::new(),
                dtb: Vec::new(),
                trailer: Vec::new(),
            },
        };
        Ok(image)
    }

    /// An image of `header` with the sections given and nothing after them.
    pub fn new(header: Header, kernel: Vec<u8>, ramdisk: Vec<u8>) -> Self {
        BootImage { header, kernel, ramdisk, second: Vec::new(), dtbo: Vec::new(), dtb: Vec::new(), trailer: Vec::new() }
    }

    pub fn header_version(&self) -> u32 {
        self.header.header_version()
    }

    /// The page the image's sections are laid out on, as its header says.
    pub fn page_size(&self) -> usize {
        match &self.header {
            Header::V0(h) => h.page_size as usize,
            Header::V3(_) => V3_PAGE,
        }
    }

    /// The image with sizes taken from its parts. A version 4 header keeps
    /// its version but carries no boot signature; unlocked bootloaders do
    /// not ask for one. Whatever followed the stock image's sections is
    /// appended after them again, as OPPO's bootloader wants.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let size = |part: &[u8], what: &str| u32::try_from(part.len()).with_context(|| format!("{what} size"));
        let mut header = self.header.clone();
        match &mut header {
            Header::V0(h) => {
                h.kernel_size = size(&self.kernel, "kernel")?;
                h.ramdisk_size = size(&self.ramdisk, "ramdisk")?;
                h.second_bootloader_size = size(&self.second, "second stage bootloader")?;
                match &mut h.versioned {
                    HeaderV0Versioned::V0 => anyhow::ensure!(
                        self.dtbo.is_empty() && self.dtb.is_empty(),
                        "a version 0 image holds no recovery DTBO and no device tree"
                    ),
                    HeaderV0Versioned::V1 { recovery_dtbo_size, .. } => {
                        *recovery_dtbo_size = size(&self.dtbo, "recovery DTBO")?;
                        anyhow::ensure!(self.dtb.is_empty(), "a version 1 image holds no device tree");
                    }
                    HeaderV0Versioned::V2 { recovery_dtbo_size, dtb_size, .. } => {
                        *recovery_dtbo_size = size(&self.dtbo, "recovery DTBO")?;
                        *dtb_size = size(&self.dtb, "device tree")?;
                    }
                }
            }
            Header::V3(h) => {
                h.kernel_size = size(&self.kernel, "kernel")?;
                h.ramdisk_size = size(&self.ramdisk, "ramdisk")?;
                h.v4_signature_size = h.v4_signature_size.map(|_| 0);
            }
        }
        let page = self.page_size();
        let mut out = Vec::new();
        header.write(&mut out).context("write header")?;
        pad(&mut out, page);
        out.extend_from_slice(&self.kernel);
        pad(&mut out, page);
        out.extend_from_slice(&self.ramdisk);
        pad(&mut out, page);
        if matches!(header, Header::V0(_)) {
            out.extend_from_slice(&self.second);
            pad(&mut out, page);
            out.extend_from_slice(&self.dtbo);
            pad(&mut out, page);
            out.extend_from_slice(&self.dtb);
            pad(&mut out, page);
        }
        out.extend_from_slice(&self.trailer);
        Ok(out)
    }
}

fn pad(out: &mut Vec<u8>, page: usize) {
    out.resize(out.len().div_ceil(page) * page, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use abootimg_oxide::{HeaderV0, HeaderV0Versioned, OsVersionPatch};

    /// A version 0 image as OPPO's phones carry it: page 2048, a kernel, a
    /// ramdisk and a signature patch after them.
    fn image(patch: &[u8]) -> Vec<u8> {
        let header = HeaderV0 {
            kernel_size: 0,
            kernel_addr: 0x8000_8000,
            ramdisk_size: 0,
            ramdisk_addr: 0x8100_0000,
            second_bootloader_size: 0,
            second_bootloader_addr: 0,
            tags_addr: 0x8000_0100,
            page_size: 2048,
            osversionpatch: OsVersionPatch(0),
            board_name: [0; 16],
            hash_digest: [0; 32],
            cmdline: Box::new([0; 1536]),
            versioned: HeaderV0Versioned::V0,
        };
        let mut bytes = BootImage::new(Header::V0(header), vec![7; 3000], vec![9; 100]).to_bytes().unwrap();
        bytes.extend_from_slice(patch);
        bytes
    }

    #[test]
    fn a_version_0_image_keeps_its_patch_and_its_page() {
        let patch: Vec<u8> = (0..1280u32).map(|i| (i % 251) as u8 + 1).collect();
        let bytes = image(&patch);
        let back = BootImage::parse(&bytes).unwrap();
        assert_eq!(back.header_version(), 0);
        assert_eq!(back.page_size(), 2048);
        assert_eq!(back.kernel, vec![7; 3000]);
        assert_eq!(back.ramdisk, vec![9; 100]);
        assert_eq!(back.trailer, patch, "the signature patch travels on");
        assert_eq!(back.to_bytes().unwrap(), bytes, "and the image is written as it was read");
    }

    #[test]
    fn a_partition_after_the_image_is_not_a_patch() {
        let patch: Vec<u8> = (0..1280u32).map(|i| (i % 251) as u8 + 1).collect();
        let whole = image(&patch);
        let mut padded = whole.clone();
        padded.resize(64 << 20, 0);
        let back = BootImage::parse(&padded).unwrap();
        assert_eq!(back.trailer, patch, "the patch is kept and the partition's padding is not");
        assert_eq!(back.to_bytes().unwrap(), whole, "the image comes back without the partition's zeros");
    }

    #[test]
    fn sections_are_laid_out_on_the_header_page() {
        let bytes = image(&[]);
        assert_eq!(&bytes[..8], b"ANDROID!");
        assert_eq!(u32::from_le_bytes(bytes[36..40].try_into().unwrap()), 2048);
        assert_eq!(&bytes[2048..2051], &[7, 7, 7], "the kernel starts at the first page");
        let ramdisk = 2048 + 3000usize.div_ceil(2048) * 2048;
        assert_eq!(&bytes[ramdisk..ramdisk + 2], &[9, 9], "the ramdisk follows the kernel");
    }
}
