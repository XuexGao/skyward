//! The older layout, which the phone's hardware services still speak. A
//! call in it carries plain numbers the way the newer one does, but hands
//! anything longer over as an address: the driver copies what the address
//! points at into the far side's own room and rewrites the address to
//! match. Where the newer layout writes a length and then the bytes, this
//! one writes a frame saying where the bytes are, and then an address for
//! the bytes themselves pointing back at that frame.

use crate::parcel::Payload;
use anyhow::{bail, Context, Result};

/// An address a call hands over, as the driver carries it.
const ADDRESS: u32 = u32::from_be_bytes([b'p', b't', b'*', 0x85]);

/// An object in the sending process, as the driver carries it.
const OBJECT: u32 = u32::from_be_bytes([b's', b'h', b'*', 0x85]);

/// The bytes this address points at sit inside what another address of the
/// same call points at.
const INSIDE_ANOTHER: u32 = 1;

/// How much room an address takes among the values.
const ADDRESS_BYTES: usize = 40;

/// How much room an object takes among the values. The newer layout adds a
/// word saying how far the object's interface travels; this one does not.
const OBJECT_BYTES: usize = 24;

/// A frame as the phone's own libraries hold one in memory: where the bytes
/// are, how many there are, and whether whoever holds it frees them.
const FRAME_BYTES: usize = 16;

/// What the driver copies for an address is rounded up to a whole word.
const WORD: u64 = 8;

/// A call being written. What the addresses point at is kept here too, so
/// it stays where it is until the driver has read it.
#[derive(Default)]
pub struct Message {
    data: Vec<u8>,
    addresses: Vec<u64>,
    held: Vec<Box<[u8]>>,
    pointed: u64,
}

impl Message {
    /// A call to `interface`, opened with the name the far side checks
    /// before it looks at anything the method itself takes.
    pub fn call(interface: &str) -> Message {
        let mut m = Message::default();
        m.data.extend_from_slice(interface.as_bytes());
        m.data.push(0);
        m
    }

    pub fn u32(&mut self, v: u32) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    /// A 64-bit number, which the phone's own writer puts on a boundary of
    /// eight: it writes every number the same way, and a value wider than a
    /// word is padded up to its own width first.
    pub fn u64(&mut self, v: u64) {
        while !self.data.len().is_multiple_of(WORD as usize) {
            self.data.push(0);
        }
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    /// Where the values stand now, for [`Message::fill`] to come back to.
    pub fn mark(&self) -> usize {
        self.data.len()
    }

    /// Write at `mark` how many bytes were written since it, which is how a
    /// structure says how long its own fields are. The four bytes counted
    /// are the ones the length itself takes.
    pub fn fill(&mut self, mark: usize) {
        let length = (self.data.len() - mark - 4) as u32;
        self.data[mark..mark + 4].copy_from_slice(&length.to_le_bytes());
    }

    /// A run of bytes: the frame that says where they are, then an address
    /// for the bytes themselves.
    pub fn bytes(&mut self, value: &[u8]) {
        let at = self.keep(value.to_vec());
        self.framed(at, value.len(), value.len());
    }

    /// Text, which is a run of bytes with a terminator the count leaves
    /// out.
    pub fn text(&mut self, value: &str) {
        let mut raw = value.as_bytes().to_vec();
        raw.push(0);
        let at = self.keep(raw);
        self.framed(at, value.len(), value.len() + 1);
    }

    /// Hold on to bytes the driver will read, and say where they are.
    fn keep(&mut self, bytes: Vec<u8>) -> u64 {
        let bytes = bytes.into_boxed_slice();
        let at = bytes.as_ptr() as u64;
        self.held.push(bytes);
        at
    }

    /// The pair of addresses a run of bytes is written as: the frame, and
    /// then the bytes it points at.
    fn framed(&mut self, at: u64, count: usize, length: usize) {
        let mut frame = Vec::with_capacity(FRAME_BYTES);
        frame.extend_from_slice(&at.to_le_bytes());
        frame.extend_from_slice(&(count as u32).to_le_bytes());
        // Whoever reads the frame does not free what it points at.
        frame.extend_from_slice(&[0; 4]);
        let frame_at = self.keep(frame);
        let parent = self.address(frame_at, FRAME_BYTES, None);
        self.address(at, length, Some(parent));
    }

    /// Write an address among the values and say where it sits, which is
    /// how the driver finds it. The answer is which address this is, for
    /// the one pointing inside it to name.
    fn address(&mut self, at: u64, length: usize, inside: Option<usize>) -> usize {
        let which = self.addresses.len();
        // An address is one of the values, so it goes where a value goes.
        while !self.data.len().is_multiple_of(WORD as usize) {
            self.data.push(0);
        }
        self.addresses.push(self.data.len() as u64);
        self.data.extend_from_slice(&ADDRESS.to_le_bytes());
        self.data.extend_from_slice(&inside.map_or(0, |_| INSIDE_ANOTHER).to_le_bytes());
        self.data.extend_from_slice(&at.to_le_bytes());
        self.data.extend_from_slice(&(length as u64).to_le_bytes());
        self.data.extend_from_slice(&(inside.unwrap_or(0) as u64).to_le_bytes());
        // The address inside the frame is the frame's first field.
        self.data.extend_from_slice(&0u64.to_le_bytes());
        self.pointed += (length as u64).next_multiple_of(WORD);
        which
    }
}

impl Payload for Message {
    fn values(&self) -> &[u8] {
        &self.data
    }

    fn addresses(&self) -> &[u64] {
        &self.addresses
    }

    fn pointed(&self) -> u64 {
        self.pointed
    }
}

/// Reads back what a hardware service answered.
pub struct Answer<'a> {
    data: &'a [u8],
    at: usize,
}

/// A structure the far side wrote, as the two numbers that say it is there
/// and how long it is.
pub type Structure = usize;

impl<'a> Answer<'a> {
    pub fn new(data: &'a [u8]) -> Answer<'a> {
        Answer { data, at: 0 }
    }

    /// Whether the call went through. A service that refused says so first,
    /// and says why in the text that follows.
    pub fn status(&mut self) -> Result<()> {
        let code = self.i32().context("read whether the service took the call")?;
        if code == 0 {
            return Ok(());
        }
        match self.text() {
            Ok(why) if !why.is_empty() => bail!("the service refused the call: {why}"),
            _ => bail!("the service refused the call with its code {code}"),
        }
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().expect("four bytes")))
    }

    /// A truth value: a byte, padded to four as everything is.
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.take(4)?[0] != 0)
    }

    /// A count the far side wrote before a list.
    pub fn count(&mut self) -> Result<u32> {
        Ok(self.i32()? as u32)
    }

    /// A 64-bit number, which the far side puts on a boundary of eight:
    /// whatever room is left of a word before it is passed over.
    pub fn number(&mut self) -> Result<u64> {
        if !self.at.is_multiple_of(8) {
            let skip = 8 - self.at % 8;
            self.take(skip).context("step over the room before a number")?;
        }
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes")))
    }

    /// Open a structure the far side wrote: it is there, and its own fields
    /// are this many bytes long. The bytes it covers run to
    /// [`Answer::go`]; the two words that say so are not counted.
    pub fn structure(&mut self) -> Result<Structure> {
        let there = self.i32().context("read whether a structure is there")?;
        if there == 0 {
            bail!("the far side left out a structure");
        }
        let length = self.i32().context("read how long a structure is")?;
        if length < 0 {
            bail!("a structure says it is {length} bytes long");
        }
        Ok(self.at + length as usize)
    }

    /// Step to the end of a structure, past whatever was left unread of it.
    pub fn go(&mut self, end: Structure) -> Result<()> {
        if end > self.data.len() || end < self.at {
            bail!("a structure ends at {end}, and what is read is at {} of {}", self.at, self.data.len());
        }
        self.at = end;
        Ok(())
    }

    /// A list of key parameters, each a structure of its own: a tag, and
    /// the value that came with it.
    pub fn parameters(&mut self) -> Result<Vec<Parameter>> {
        let mut out = Vec::new();
        let count = self.count().context("read how many parameters there are")?;
        for _ in 0..count {
            let end = self.structure().context("read a parameter")?;
            let tag = self.count().context("read what a parameter is tagged with")?;
            let parameter = match tag >> 28 {
                // An enumeration, an integer, a truth value and a
                // repeatable number are all one word.
                1 | 2 | 3 | 4 | 7 => Parameter { tag: tag & 0x0fff_ffff, number: Some(self.i32()? as i64), bytes: None },
                // A long or a date is two.
                5 | 6 | 10 => Parameter { tag: tag & 0x0fff_ffff, number: Some(self.number()? as i64), bytes: None },
                // A big number is its length and then its digits.
                8 => Parameter { tag: tag & 0x0fff_ffff, number: Some(self.pointed()?.len() as i64), bytes: None },
                // Bytes are a run of them.
                9 => Parameter { tag: tag & 0x0fff_ffff, number: None, bytes: Some(self.pointed()?.to_vec()) },
                other => bail!("a parameter is tagged {other:#x}, which is no kind of value"),
            };
            self.go(end).context("step to the end of a parameter")?;
            out.push(parameter);
        }
        Ok(out)
    }

    /// The bytes an address in the reply points at. The driver has already
    /// moved them into this program's own room and rewritten the address,
    /// so they are read where they lie.
    pub fn pointed(&mut self) -> Result<&'a [u8]> {
        let raw = self.take(ADDRESS_BYTES)?;
        let kind = u32::from_le_bytes(raw[0..4].try_into().expect("four bytes"));
        if kind != ADDRESS {
            bail!("the reply holds {kind:#x} where an address was expected");
        }
        let at = u64::from_le_bytes(raw[8..16].try_into().expect("eight bytes"));
        let length = u64::from_le_bytes(raw[16..24].try_into().expect("eight bytes"));
        if at == 0 {
            bail!("the service left out something the call asked for");
        }
        Ok(unsafe { std::slice::from_raw_parts(at as *const u8, length as usize) })
    }

    /// Text the far side wrote as its own value rather than as a frame.
    fn text(&mut self) -> Result<String> {
        let units = self.i32()?;
        if units < 0 {
            bail!("text of length {units} was read where some was expected");
        }
        let raw = self.take((units as usize + 1) * 2)?;
        while !self.at.is_multiple_of(4) && self.at < self.data.len() {
            self.at += 1;
        }
        let utf16: Vec<u16> = raw[..units as usize * 2].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        Ok(String::from_utf16_lossy(&utf16))
    }

    /// The handle of an object in the answering process.
    pub fn object(&mut self) -> Result<Option<u32>> {
        let raw = self.take(OBJECT_BYTES)?;
        let kind = u32::from_le_bytes(raw[0..4].try_into().expect("four bytes"));
        let handle = u32::from_le_bytes(raw[8..12].try_into().expect("four bytes"));
        Ok((kind == OBJECT).then_some(handle))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at + n;
        if end > self.data.len() {
            bail!("the reply holds {} bytes, {n} more were read at {}", self.data.len(), self.at);
        }
        let out = &self.data[self.at..end];
        self.at = end;
        Ok(out)
    }
}

/// One of the parameters the key service answers with: what it is tagged
/// with, and the value that came with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    /// The tag's number, without the kind of value it carries.
    pub tag: u32,
    /// The number it carries, where it carries one: an enumeration, an
    /// integer, a long, a date, or the length of a big number.
    pub number: Option<i64>,
    /// The bytes it carries, where it carries bytes.
    pub bytes: Option<Vec<u8>>,
}

/// Says something in the one place there is to say it: the kernel's own
/// log, which is still there when nothing else is running to keep one.
#[cfg(target_os = "android")]
fn tell_kernel(line: &str) {
    use std::io::Write;
    if let Ok(mut log) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        let _ = writeln!(log, "skyward: {line}");
    }
}

/// The hardware service serving `interface` as `instance`, or `None` while
/// nothing has registered it.
#[cfg(target_os = "android")]
pub fn find<'a>(binder: &'a crate::driver::Binder, interface: &str, instance: &str) -> Result<Option<crate::driver::Handle<'a>>> {
    use crate::driver::Handle;
    // The directory the phone's hardware services register with, which is
    // a second one beside the directory the rest of the phone uses, and
    // the call that asks it for a service.
    const DIRECTORY: &str = "android.hidl.manager@1.0::IServiceManager";
    const GET: u32 = 1;
    let directory = binder.directory()?;
    let mut call = Message::call(DIRECTORY);
    call.text(interface);
    call.text(instance);
    // The directory answers only once the daemon that keeps it has taken
    // the driver for its own, and that happens a moment after it starts: a
    // call made before then is refused outright, and the refusal reads the
    // same as an answer that nothing has registered. Make the call again
    // for a while before believing it, and keep what the driver said.
    let reply = {
        let mut tries = 0;
        loop {
            match directory.transact(GET, &call) {
                Ok(reply) => break reply,
                Err(e) => {
                    tries += 1;
                    tell_kernel(&format!(
                        "look up {interface}/{instance} was refused on try {tries}: {e:#}; the call carries {} bytes over {} addresses",
                        call.values().len(),
                        call.addresses().len()
                    ));
                    if tries == 5 {
                        return Err(e).with_context(|| format!("look up {interface}/{instance}"));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }
    };
    let mut read = Answer::new(reply.bytes());
    read.status().with_context(|| format!("look up {interface}/{instance}"))?;
    match read.object().with_context(|| format!("read what the directory answered for {interface}"))? {
        Some(handle) => Ok(Some(Handle::hold(reply.binder(), handle)?)),
        None => Ok(None),
    }
}

/// The name a hardware service gives for the interface it was reached by,
/// which is what a call that changes nothing answers.
#[cfg(target_os = "android")]
pub fn describes(service: &crate::driver::Handle) -> Result<String> {
    // Every hardware service serves this interface besides its own, and a
    // call on it is named as being on it whatever else the service serves.
    const BASE: &str = "android.hidl.base@1.0::IBase";
    const DESCRIBE: u32 = 256_136_003;
    let reply = service.transact(DESCRIBE, &Message::call(BASE)).context("ask the service what it serves")?;
    let mut read = Answer::new(reply.bytes());
    read.status().context("ask the service what it serves")?;
    let frame = read.pointed().context("read the frame of what the service serves")?;
    if frame.len() < FRAME_BYTES {
        bail!("the service answered a frame of {} bytes", frame.len());
    }
    let name = read.pointed().context("read the name of what the service serves")?;
    Ok(String::from_utf8_lossy(name.strip_suffix(&[0]).unwrap_or(name)).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads the parts of a written call back out of its own memory, the
    /// way the driver does: the values, and each address among them.
    fn written(m: &Message) -> Vec<(u32, u64, Vec<u8>)> {
        m.addresses
            .iter()
            .map(|at| {
                let raw = &m.data[*at as usize..*at as usize + ADDRESS_BYTES];
                let flags = u32::from_le_bytes(raw[4..8].try_into().unwrap());
                let points = u64::from_le_bytes(raw[8..16].try_into().unwrap());
                let length = u64::from_le_bytes(raw[16..24].try_into().unwrap()) as usize;
                let inside = u64::from_le_bytes(raw[24..32].try_into().unwrap());
                let bytes = unsafe { std::slice::from_raw_parts(points as *const u8, length) }.to_vec();
                assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), ADDRESS);
                assert_eq!(u64::from_le_bytes(raw[32..40].try_into().unwrap()), 0);
                (flags, inside, bytes)
            })
            .collect()
    }

    #[test]
    fn a_call_opens_with_the_interface_name_and_a_terminator() {
        let m = Message::call("a.b@1.0::IC");
        assert_eq!(&m.data[..11], b"a.b@1.0::IC");
        assert_eq!(m.data.len(), 12, "the name and its terminator, and nothing else");
        assert_eq!(m.data[11], 0);
        assert!(m.addresses.is_empty());
    }

    /// A name whose length leaves a remainder is written as it is, and not
    /// padded to a whole word: the far side reads exactly the name and its
    /// terminator before the method's own arguments, so padding here would
    /// put every one of them out by as many bytes as were added. A name
    /// whose length is a multiple of four, as `a.b@1.0::IC` is, cannot show
    /// this, which is why the rest of these tests use longer ones.
    #[test]
    fn a_name_whose_length_leaves_a_remainder_is_not_padded() {
        let m = Message::call("android.hidl.manager@1.0::IServiceManager");
        // Forty-one bytes of name and its terminator: forty-two, which is
        // not a whole number of words.
        assert_eq!(m.data.len(), 42, "the name and its terminator, with no room added");
        assert_eq!(m.data[41], 0);
    }

    /// And the arguments after such a name start where the name ends.
    #[test]
    fn the_arguments_after_a_name_whose_length_leaves_a_remainder_follow_it() {
        let mut m = Message::call("android.hidl.manager@1.0::IServiceManager");
        m.u32(7);
        assert_eq!(u32::from_le_bytes(m.data[42..46].try_into().unwrap()), 7, "right after the terminator");
    }

    #[test]
    fn numbers_are_written_where_they_fall() {
        let mut m = Message::call("a.b@1.0::IC");
        m.u32(7);
        m.u64(1 << 40);
        assert_eq!(m.data.len(), 12 + 4 + 8, "a word is not moved to a boundary of its own");
        assert_eq!(u32::from_le_bytes(m.data[12..16].try_into().unwrap()), 7);
        assert_eq!(u64::from_le_bytes(m.data[16..24].try_into().unwrap()), 1 << 40);
    }

    /// The interface's own writer puts a value wider than a word on a
    /// boundary of its width. A method number takes a word, so a call whose
    /// interface name leaves the values four bytes in from a boundary lands
    /// its number where an unaligned write would go wrong.
    #[test]
    fn a_number_wider_than_a_word_goes_on_a_boundary_of_its_own_width() {
        // Fifteen characters and a terminator: the values start at 16, and
        // one word after that is 20, which is not a boundary of eight.
        let mut m = Message::call("abcdefghijklmno");
        assert_eq!(m.data.len(), 16, "the name, its terminator, and padding to four");
        m.u32(10);
        assert_eq!(m.data.len(), 20);
        m.u64(0x0102_0304_0506_0708);
        assert_eq!(m.data.len(), 20 + 4 + 8, "four bytes of padding, then the number");
        assert_eq!(&m.data[20..24], &[0, 0, 0, 0], "the padding is zeros");
        assert_eq!(u64::from_le_bytes(m.data[24..32].try_into().unwrap()), 0x0102_0304_0506_0708);
    }

    /// A number already on a boundary takes no padding in front of it.
    #[test]
    fn a_number_already_on_a_boundary_is_not_moved() {
        let mut m = Message::call("a.b@1.0::IC");
        m.u32(10);
        assert_eq!(m.data.len(), 16, "a boundary of eight already");
        m.u64(7);
        assert_eq!(m.data.len(), 24, "no padding before it");
        assert_eq!(u64::from_le_bytes(m.data[16..24].try_into().unwrap()), 7);
    }

    /// An address is one of the values, and the interface's own writer
    /// keeps its addresses on boundaries of eight as well.
    #[test]
    fn an_address_starts_on_a_boundary_of_eight() {
        let mut m = Message::call("a.b@1.0::IC");
        m.u32(1);
        m.bytes(&[9; 4]);
        for at in &m.addresses {
            assert_eq!(at % 8, 0, "an address at {at} is not on a boundary of eight");
        }
    }

    #[test]
    fn bytes_are_written_as_a_frame_and_the_bytes_it_points_at() {
        let mut m = Message::call("a.b@1.0::IC");
        m.bytes(&[1, 2, 3]);
        let parts = written(&m);
        assert_eq!(parts.len(), 2, "the frame, then the bytes");
        assert_eq!(parts[0].0, 0, "the frame points inside nothing");
        assert_eq!(parts[0].2.len(), FRAME_BYTES);
        assert_eq!(u32::from_le_bytes(parts[0].2[8..12].try_into().unwrap()), 3, "how many bytes there are");
        assert_eq!(parts[1].0, INSIDE_ANOTHER, "the bytes sit inside the frame");
        assert_eq!(parts[1].1, 0, "inside the first address of the call");
        assert_eq!(parts[1].2, vec![1, 2, 3]);
        assert_eq!(m.pointed, FRAME_BYTES as u64 + WORD, "both rounded up to a word");
    }

    #[test]
    fn text_counts_its_characters_and_carries_a_terminator() {
        let mut m = Message::call("a.b@1.0::IC");
        m.text("default");
        let parts = written(&m);
        assert_eq!(u32::from_le_bytes(parts[0].2[8..12].try_into().unwrap()), 7, "the terminator is not counted");
        assert_eq!(parts[1].2, b"default\0", "but it is carried");
    }

    #[test]
    fn the_frame_points_at_the_bytes_that_follow_it() {
        let mut m = Message::call("a.b@1.0::IC");
        m.bytes(&[9; 5]);
        let parts = written(&m);
        let in_frame = u64::from_le_bytes(parts[0].2[0..8].try_into().unwrap());
        let raw = &m.data[m.addresses[1] as usize..];
        assert_eq!(in_frame, u64::from_le_bytes(raw[8..16].try_into().unwrap()));
    }

    /// A reply as the key service writes one: a status that says the call
    /// went through, then what the method answers.
    fn reply(fields: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut out = 0i32.to_le_bytes().to_vec();
        fields(&mut out);
        out
    }

    #[test]
    fn a_structure_says_that_it_is_there_and_how_long_its_own_fields_are() {
        let data = reply(|p| {
            p.extend_from_slice(&1i32.to_le_bytes());
            // Eight bytes of its own: two words, which is what the length
            // counts. The two words that say so are not counted.
            p.extend_from_slice(&8i32.to_le_bytes());
            p.extend_from_slice(&7u32.to_le_bytes());
            p.extend_from_slice(&9u32.to_le_bytes());
        });
        let mut read = Answer::new(&data);
        read.status().unwrap();
        let end = read.structure().unwrap();
        assert_eq!(end, 20, "the status and the structure's own two words, then its eight bytes");
        assert_eq!(read.count().unwrap(), 7);
        read.go(end).unwrap();
    }

    #[test]
    fn a_structure_the_far_side_left_out_is_an_error() {
        let data = reply(|p| p.extend_from_slice(&0i32.to_le_bytes()));
        let mut read = Answer::new(&data);
        read.status().unwrap();
        assert!(read.structure().is_err());
    }

    /// The numbers in a reply are laid out as the instructions say: a
    /// value wider than a word goes on a boundary of its own width.
    #[test]
    fn a_number_in_a_reply_is_read_from_its_own_boundary() {
        // Four bytes of status, then one word, then the room left before a
        // boundary of eight, then the number.
        let data = reply(|p| {
            p.extend_from_slice(&1u32.to_le_bytes());
            p.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        });
        let mut read = Answer::new(&data);
        read.status().unwrap();
        assert_eq!(read.number().unwrap(), 0x0102_0304_0506_0708);

        // Status and two words make twelve bytes, which is not a boundary
        // of eight; the four bytes that are left of the word before the
        // number are padding, and the number follows them.
        let shifted = reply(|p| {
            p.extend_from_slice(&1u32.to_le_bytes());
            p.extend_from_slice(&2u32.to_le_bytes());
            p.extend_from_slice(&[0; 4]);
            p.extend_from_slice(&7u64.to_le_bytes());
        });
        let mut read = Answer::new(&shifted);
        read.status().unwrap();
        assert_eq!(read.count().unwrap(), 1, "the first word");
        assert_eq!(read.count().unwrap(), 2, "the second");
        assert_eq!(read.number().unwrap(), 7, "the number after the room left of a word");
    }

    #[test]
    fn a_parameter_is_read_with_the_kind_of_value_it_carries() {
        // An enumeration tag is twenty-eight bits of kind and a number; a
        // long carries two words.
        let enum_tag = ((1u32 << 28) | 4).to_le_bytes();
        let long_tag = ((5u32 << 28) | 200).to_le_bytes();
        let data = reply(|p| {
            p.extend_from_slice(&2u32.to_le_bytes());
            // A parameter's own fields: its tag, then its value. Each is a
            // structure of its own, and says how long it is.
            let mut first = enum_tag.to_vec();
            first.extend_from_slice(&32u32.to_le_bytes());
            p.extend_from_slice(&1i32.to_le_bytes());
            p.extend_from_slice(&(first.len() as i32).to_le_bytes());
            p.extend_from_slice(&first);
            // A long is written on a boundary of eight, so the room left of
            // the word before it goes by first.
            let mut second = long_tag.to_vec();
            second.extend_from_slice(&[0; 4]);
            second.extend_from_slice(&65537u64.to_le_bytes());
            p.extend_from_slice(&1i32.to_le_bytes());
            p.extend_from_slice(&(second.len() as i32).to_le_bytes());
            p.extend_from_slice(&second);
        });
        let mut read = Answer::new(&data);
        read.status().unwrap();
        let params = read.parameters().unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], Parameter { tag: 4, number: Some(32), bytes: None }, "a block mode of GCM");
        assert_eq!(params[1], Parameter { tag: 200, number: Some(65537), bytes: None }, "an RSA public exponent");
    }

    #[test]
    fn a_parameter_of_no_known_kind_is_an_error() {
        let tag = (0u32 << 28).to_le_bytes();
        let data = reply(|p| {
            p.extend_from_slice(&1u32.to_le_bytes());
            p.extend_from_slice(&1i32.to_le_bytes());
            p.extend_from_slice(&8i32.to_le_bytes());
            p.extend_from_slice(&tag);
            p.extend_from_slice(&0u32.to_le_bytes());
        });
        let mut read = Answer::new(&data);
        read.status().unwrap();
        assert!(read.parameters().is_err());
    }

    #[test]
    fn a_structure_says_how_long_its_own_fields_are() {
        let mut m = Message::call("a.b@1.0::IC");
        m.u32(4);
        let at = m.mark();
        m.u32(0);
        m.u32(7);
        m.u32(9);
        m.fill(at);
        let length = u32::from_le_bytes(m.data[at..at + 4].try_into().unwrap());
        assert_eq!(length, 8, "the two words after the length, and not the length itself");
    }

    #[test]
    fn a_service_that_refused_the_call_is_an_error() {
        let mut reply = 3i32.to_le_bytes().to_vec();
        reply.extend_from_slice(&(-1i32).to_le_bytes());
        assert!(Answer::new(&reply).status().is_err());
        assert!(Answer::new(&0i32.to_le_bytes()).status().is_ok());
    }

    #[test]
    fn reading_past_the_end_of_a_reply_is_an_error() {
        assert!(Answer::new(&[]).i32().is_err());
        assert!(Answer::new(&[0; 8]).pointed().is_err());
    }

    #[test]
    fn a_truth_value_is_a_byte_padded_to_four() {
        let mut read = Answer::new(&[1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0]);
        assert!(read.bool().unwrap());
        assert!(!read.bool().unwrap());
        assert_eq!(read.i32().unwrap(), 7, "what follows it starts four bytes on");
        assert!(Answer::new(&[1, 0]).bool().is_err());
    }
}
