//! The key service of the phones whose secure world speaks the older
//! hardware interface: `android.hardware.keymaster@3.0`. The OPPO R9s and
//! A57, and every phone built before Android 11, keep their file keys here
//! rather than in the newer `IKeyMintDevice` that [`crate::keymint`]
//! reaches.
//!
//! The service is reached over the second binder driver, the one the
//! phone's hardware services register with, and every call is written the
//! way that driver carries values: numbers as they are, and everything
//! longer than a number as an address (see [`skyward_binder::hidl`]).
//!
//! A key the service wrapped never comes out as itself: what the service
//! does is unwrap it under what the caller says it is bound to and the
//! note that proves who asked. That is what each user's file key is kept
//! behind.

use crate::token::Token;
use anyhow::{bail, Context, Result};
use skyward_binder::driver::{Binder, Handle};
use skyward_binder::hidl::{self, Answer, Message, Parameter};

/// The hardware service, and the instance it serves as.
pub const SERVICE: &str = "android.hardware.keymaster@3.0::IKeymasterDevice";
const INSTANCE: &str = "default";

/// The methods, as the interface numbers them. A phone's own library
/// numbers them by their order in the interface, which starts at one:
/// `addRngEntropy` is the first, and `abort` the last.
const GET_HARDWARE_FEATURES: u32 = 1;
const GET_KEY_CHARACTERISTICS: u32 = 4;
const UPGRADE_KEY: u32 = 7;
const BEGIN: u32 = 10;
const UPDATE: u32 = 11;
const FINISH: u32 = 12;
const ABORT: u32 = 13;

// The tags, as `android.hardware.keymaster@3.0::Tag` numbers them: the kind
// of value it carries in the top bits, then its own number. The kind is
// what decides how the value after it is written.
const KIND_ENUM: u32 = 1 << 28;
const KIND_UINT: u32 = 3 << 28;
const KIND_BYTES: u32 = 9 << 28;
const TAG_PURPOSE: u32 = KIND_ENUM | 1;
const TAG_BLOCK_MODE: u32 = KIND_ENUM | 4;
const TAG_PADDING: u32 = KIND_ENUM | 6;
const TAG_APPLICATION_ID: u32 = KIND_BYTES | 601;
const TAG_NONCE: u32 = KIND_BYTES | 1001;
const TAG_MAC_LENGTH: u32 = KIND_UINT | 1003;

/// The tag stripped of the kind of value it carries, which is how the same
/// tag reads in the newer interface.
const TAG_NUMBER: u32 = 0x0fff_ffff;

// The values, as `KeyPurpose`, `BlockMode` and `PaddingMode` number them.
const PURPOSE_DECRYPT: u32 = 1;
const BLOCK_MODE_GCM: u32 = 32;
const PADDING_NONE: u32 = 1;

/// How long the tag of a GCM key is, in bits. Everything the phone wraps is
/// wrapped with the whole of it.
const GCM_TAG_BITS: u32 = 128;

/// How long the nonce of a GCM key is.
const NONCE_BYTES: usize = 12;

/// What the phone says about its key hardware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Features {
    pub version: i32,
    pub security_level: i32,
    /// The kinds of key it can make and use, each a number of its own.
    pub algorithms: Vec<u32>,
}

/// The phone's key service, as this program talks to it.
pub struct Keymaster<'a> {
    device: Handle<'a>,
}

impl<'a> Keymaster<'a> {
    /// Reach the running key service, or say that none is.
    pub fn open(hardware: &'a Binder) -> Result<Keymaster<'a>> {
        let device = hidl::find(hardware, SERVICE, INSTANCE)?
            .with_context(|| format!("{SERVICE}/{INSTANCE} is not running; the phone's key service has to be started first"))?;
        Ok(Keymaster { device })
    }

    /// What the service says about itself. It changes nothing and takes no
    /// key, so it is what to call to see that the service answers.
    pub fn features(&self) -> Result<Features> {
        let reply = self.device.transact(GET_HARDWARE_FEATURES, &Message::call(SERVICE)).context("ask the key service about itself")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("ask the key service about itself")?;
        let version = read.i32().context("read the key service's version")?;
        let security_level = read.i32().context("read where the key service runs")?;
        let mut algorithms = Vec::new();
        for _ in 0..read.count().context("read how many kinds of key the service makes")? {
            algorithms.push(read.count().context("read a kind of key")?);
        }
        Ok(Features { version, security_level, algorithms })
    }

    /// What the service says a key is bound to and may be used for.
    pub fn characteristics(&self, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<Parameter>> {
        let mut call = Message::call(SERVICE);
        call.bytes(key_blob);
        call.bytes(app_id);
        call.bytes(&[]);
        let reply = self.device.transact(GET_KEY_CHARACTERISTICS, &call).context("ask what the key may be used for")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("ask what the key may be used for")?;
        let code = read.i32().context("read whether the key may be used")?;
        if code != 0 {
            bail!("the key service answered {code} for what the key may be used for");
        }
        // What the key may be used for is one structure holding two lists:
        // what software checks, and what the secure world checks. The
        // counts stand at the same places in each of the two frames.
        let header = read.pointed().context("read what the key may be used for")?;
        if header.len() < 2 * FRAME_BYTES {
            bail!("what the key may be used for is {} bytes", header.len());
        }
        let software = u32::from_le_bytes(header[8..12].try_into().expect("four bytes")) as usize;
        let secure = u32::from_le_bytes(header[24..28].try_into().expect("four bytes")) as usize;
        let mut out = read_parameters_of(&mut read, software).context("read what software checks")?;
        out.extend(read_parameters_of(&mut read, secure).context("read what the secure world checks")?);
        Ok(out)
    }

    /// Undo an AES-GCM encryption the service did with `key_blob`. The
    /// service only hands back the plaintext when `app_id` is the one the
    /// key was made for, so a wrong secret fails here rather than yielding
    /// something that looks like a key. A key guarded by a screen lock
    /// takes the note the secure world wrote when it was answered.
    pub fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8], note: Option<&Token>) -> Result<Vec<u8>> {
        let operation = self.begin(key_blob, app_id, nonce, note)?;
        let mut out = self.update(&operation, body)?;
        out.extend_from_slice(&self.finish(&operation)?);
        Ok(out)
    }

    /// A key for the firmware running now, from one made under an older
    /// build. It is bound to the same thing, which has to be given again.
    pub fn upgrade(&self, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<u8>> {
        let mut call = Message::call(SERVICE);
        call.bytes(key_blob);
        let params = [Param { tag: TAG_APPLICATION_ID, number: 0, bytes: app_id }];
        write_parameters(&mut call, &params);
        let reply = self.device.transact(UPGRADE_KEY, &call).context("renew the key")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("renew the key")?;
        let code = read.i32().context("read whether the key was renewed")?;
        if code != 0 {
            bail!("the key service answered {code} for the renewed key");
        }
        read.bytes().context("read the renewed key")
    }

    /// Open a decryption with the key service and keep hold of it.
    fn begin(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], note: Option<&Token>) -> Result<Handle<'a>> {
        let params = gcm_parameters(app_id, nonce);
        let mut call = Message::call(SERVICE);
        call.u32(PURPOSE_DECRYPT);
        call.bytes(key_blob);
        write_parameters(&mut call, &params);
        // A key guarded by the screen lock takes the note the secure world
        // wrote when it was answered; one that is not guarded takes an empty
        // one, which is a note all the same.
        write_note(&mut call, note);

        // The decryption the service opens outlives the reply that named
        // it, so take a share of it before the reply's room goes back.
        let reply = self.device.transact(BEGIN, &call).context("start a decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("start a decryption")?;
        let code = read.i32().context("read whether a decryption was opened")?;
        if code != 0 {
            bail!("the key service answered {code} for the decryption it was asked to open");
        }
        let handle = read.number().context("read the decryption the key service opened")?;
        read_parameters(&mut read).context("read how the decryption is set up")?;
        match handle {
            0 => bail!("the key service opened no decryption"),
            h => Ok(Handle::hold(reply.binder(), u32::try_from(h).context("the decryption's number")?)?),
        }
    }

    fn update(&self, operation: &Handle, input: &[u8]) -> Result<Vec<u8>> {
        let mut call = Message::call(SERVICE);
        call.u64(operation.number() as u64);
        write_parameters(&mut call, &[]);
        call.bytes(input);
        write_note(&mut call, None);
        let reply = operation.transact(UPDATE, &call).context("feed the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("feed the decryption")?;
        let code = read.i32().context("read whether the decryption took what it was given")?;
        if code != 0 {
            bail!("the key service answered {code} for what it was given to decrypt");
        }
        read_parameters(&mut read).context("read how the decryption is set up")?;
        let taken = read.i32().context("read how much the decryption took")?;
        if taken as usize != input.len() {
            bail!("the decryption took {taken} of the {} bytes it was given", input.len());
        }
        // A decryption whose tag is checked at the end gives nothing back
        // until then, so what it took is all this call answers with.
        Ok(Vec::new())
    }

    fn finish(&self, operation: &Handle) -> Result<Vec<u8>> {
        let mut call = Message::call(SERVICE);
        call.u64(operation.number() as u64);
        write_parameters(&mut call, &[]);
        call.bytes(&[]);
        call.bytes(&[]);
        write_note(&mut call, None);
        let reply = operation.transact(FINISH, &call).context("close the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("close the decryption, which is where a wrong key is refused")?;
        let code = read.i32().context("read whether the decryption closed")?;
        if code != 0 {
            bail!("the key service answered {code} for the decryption it had to close");
        }
        read_parameters(&mut read).context("read how the decryption is set up")?;
        read.bytes().context("read what the decryption ended with")
    }

    /// Whether the secure world will unwrap the key at all: a decryption is
    /// opened on it under a nonce of nothing and dropped again, which reads
    /// nothing and changes nothing.
    #[allow(dead_code)]
    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> Result<()> {
        let operation = self.begin(key_blob, app_id, &[0; NONCE_BYTES], None)?;
        let mut call = Message::call(SERVICE);
        call.u64(operation.number() as u64);
        let reply = operation.transact(ABORT, &call).context("drop the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("drop the decryption")?;
        let code = read.i32().context("read whether the decryption was dropped")?;
        if code != 0 {
            bail!("the key service answered {code} for the decryption it was asked to drop");
        }
        Ok(())
    }
}

/// How much room one parameter takes in the array the service reads: the
/// tag, the number its union arm holds, and the pointer and length of the
/// bytes when the arm carries bytes.
const PARAMETER_BYTES: usize = 32;

/// How far into a parameter its pointer to those bytes stands.
const PARAMETER_POINTER_OFFSET: usize = 16;

/// A frame says where a run of things is and how many there are.
const FRAME_BYTES: usize = 16;

/// How far into a note its pointer to the signature stands, and how much
/// room the note itself takes: the three numbers it says, the kind of
/// answer and the time, and then the pointer and length of the signature.
const NOTE_POINTER_OFFSET: usize = 40;
const NOTE_BYTES: usize = 56;

/// What one parameter carries: the tag that says what it is, the number the
/// union arm holds, and the bytes for the arms that carry bytes.
struct Param<'a> {
    tag: u32,
    number: u64,
    bytes: &'a [u8],
}

/// Write a list of parameters the way the interface carries one: the array
/// of structures, and then, for each structure that points at bytes, the
/// bytes it points at, named against the place inside that structure where
/// its pointer stands.
fn write_parameters(call: &mut Message, params: &[Param<'_>]) {
    let mut array = Vec::with_capacity(params.len() * PARAMETER_BYTES);
    let mut held: Vec<(u64, usize)> = Vec::with_capacity(params.len());
    for param in params {
        let length = param.bytes.len();
        let at = if length == 0 { 0 } else { call.stash(param.bytes.to_vec()) };
        held.push((at, length));
        array.extend_from_slice(&param.tag.to_le_bytes());
        array.extend_from_slice(&[0; 4]);
        array.extend_from_slice(&param.number.to_le_bytes());
        array.extend_from_slice(&at.to_le_bytes());
        array.extend_from_slice(&(length as u32).to_le_bytes());
        array.extend_from_slice(&[0; 4]);
    }
    let at = if array.is_empty() { 0 } else { call.stash(array) };
    let list = call.vec_from(at, params.len(), params.len() * PARAMETER_BYTES);
    for (index, (at, length)) in held.into_iter().enumerate() {
        call.embedded(at, length, list, (index * PARAMETER_BYTES + PARAMETER_POINTER_OFFSET) as u64);
    }
}

/// The parameters a decryption under a nonce takes, in the order the
/// interface's own library writes them.
fn gcm_parameters<'a>(app_id: &'a [u8], nonce: &'a [u8]) -> Vec<Param<'a>> {
    let mut params = vec![
        Param { tag: TAG_BLOCK_MODE, number: BLOCK_MODE_GCM as u64, bytes: &[] },
        Param { tag: TAG_PADDING, number: PADDING_NONE as u64, bytes: &[] },
        Param { tag: TAG_MAC_LENGTH, number: GCM_TAG_BITS as u64, bytes: &[] },
    ];
    if !app_id.is_empty() {
        params.push(Param { tag: TAG_APPLICATION_ID, number: 0, bytes: app_id });
    }
    params.push(Param { tag: TAG_NONCE, number: 0, bytes: nonce });
    params.push(Param { tag: TAG_PURPOSE, number: PURPOSE_DECRYPT as u64, bytes: &[] });
    params
}

/// Read a list of parameters whose length a frame before it gives.
fn read_parameters(read: &mut Answer) -> Result<Vec<Parameter>> {
    let frame = read.pointed().context("read the frame of a list of parameters")?;
    if frame.len() < FRAME_BYTES {
        bail!("a list of parameters says it is {} bytes", frame.len());
    }
    let count = u32::from_le_bytes(frame[8..12].try_into().expect("four bytes")) as usize;
    read_parameters_of(read, count)
}

/// Read `count` parameters: the array of structures, then the bytes each
/// one points at.
fn read_parameters_of(read: &mut Answer, count: usize) -> Result<Vec<Parameter>> {
    let array = read.pointed().context("read a list of parameters")?;
    if array.len() < count * PARAMETER_BYTES {
        bail!("a list of parameters is {} bytes for {count} of them", array.len());
    }
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let at = index * PARAMETER_BYTES;
        let tag = u32::from_le_bytes(array[at..at + 4].try_into().expect("four bytes"));
        let number = u64::from_le_bytes(array[at + 8..at + 16].try_into().expect("eight bytes"));
        let pointed = read.pointed().context("read what a parameter points at")?;
        let (carried, bytes) = match tag >> 28 {
            // A big number and a run of bytes are the bytes themselves.
            8 | 9 => (pointed.len() as i64, Some(pointed.to_vec())),
            // A long and a date are the whole number; the rest are a word.
            5 | 6 | 10 => (number as i64, None),
            _ => (number as u32 as i32 as i64, None),
        };
        out.push(Parameter { tag: tag & TAG_NUMBER, number: Some(carried), bytes: bytes.filter(|b| !b.is_empty()) });
    }
    Ok(out)
}

/// Write the note the secure world wrote, as the interface carries one: the
/// numbers it says and the time, then the signature over all of it, named
/// against the place inside the note where its pointer stands.
fn write_note(call: &mut Message, note: Option<&Token>) {
    let signature = note.map(|t| t.mac.as_slice()).unwrap_or(&[]);
    let length = signature.len();
    let at = if length == 0 { 0 } else { call.stash(signature.to_vec()) };
    let mut buf = Vec::with_capacity(NOTE_BYTES);
    match note {
        Some(t) => {
            buf.extend_from_slice(&t.challenge.to_le_bytes());
            buf.extend_from_slice(&t.user.to_le_bytes());
            buf.extend_from_slice(&t.authenticator.to_le_bytes());
            buf.extend_from_slice(&(t.kind as u32).to_le_bytes());
            buf.extend_from_slice(&[0; 4]);
            buf.extend_from_slice(&t.when.to_le_bytes());
        }
        None => buf.resize(NOTE_POINTER_OFFSET, 0),
    }
    buf.extend_from_slice(&at.to_le_bytes());
    buf.extend_from_slice(&(length as u32).to_le_bytes());
    buf.extend_from_slice(&[0; 4]);
    let parent = call.buffer(buf);
    call.embedded(at, length, parent, NOTE_POINTER_OFFSET as u64);
}

/// The number a tag carries, without the kind of value it is.
#[allow(dead_code)]
pub fn tag_number(tag: u32) -> u32 {
    tag & TAG_NUMBER
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyward_binder::parcel::Payload;

    #[test]
    fn the_methods_are_the_ones_the_interface_lists_in_the_order_it_lists_them() {
        // The interface lists these in this order, and a phone's own library
        // numbers them from one.
        assert_eq!(GET_HARDWARE_FEATURES, 1);
        assert_eq!(GET_KEY_CHARACTERISTICS, 4);
        assert_eq!(UPGRADE_KEY, 7);
        assert_eq!(BEGIN, 10);
        assert_eq!(UPDATE, 11);
        assert_eq!(FINISH, 12);
        assert_eq!(ABORT, 13);
    }

    /// A tag is built out of the kind of value and a number, so it is wider
    /// than a word's worth of number.
    #[test]
    fn a_tag_carries_the_kind_of_its_value_in_its_top_bits() {
        assert_eq!(TAG_PURPOSE, 0x1000_0001);
        assert_eq!(TAG_BLOCK_MODE, 0x1000_0004);
        assert_eq!(TAG_PADDING, 0x1000_0006);
        assert_eq!(TAG_MAC_LENGTH, 0x3000_03eb);
        assert_eq!(TAG_APPLICATION_ID, 0x9000_0259);
        assert_eq!(TAG_NONCE, 0x9000_03e9);
        for tag in [TAG_PURPOSE, TAG_BLOCK_MODE, TAG_PADDING, TAG_MAC_LENGTH, TAG_APPLICATION_ID, TAG_NONCE] {
            assert_eq!(tag_number(tag), tag & 0x0fff_ffff, "the number it carries, without its kind");
        }
    }

    /// One parameter takes thirty-two bytes of the array, and says where
    /// its bytes stand sixteen bytes into its own.
    #[test]
    fn a_parameter_says_where_its_bytes_stand() {
        assert_eq!(PARAMETER_BYTES, 32);
        assert_eq!(PARAMETER_POINTER_OFFSET, 16);
        let mut call = Message::call(SERVICE);
        write_parameters(&mut call, &[Param { tag: TAG_BLOCK_MODE, number: BLOCK_MODE_GCM as u64, bytes: &[] }]);
        assert_eq!(call.addresses().len(), 2, "the array, and the bytes of the one parameter that has none");
    }

    /// The parameters a decryption under a nonce takes are written in the
    /// order the interface's own library writes them, and a call for a key
    /// that is bound to nothing names no application.
    #[test]
    fn a_decryption_under_a_nonce_takes_its_parameters_in_order() {
        let params = gcm_parameters(&[1, 2], &[9; 12]);
        assert_eq!(params.len(), 6, "a decryption takes six of them");
        let tags: Vec<u32> = params.iter().map(|p| p.tag).collect();
        assert_eq!(tags, vec![TAG_BLOCK_MODE, TAG_PADDING, TAG_MAC_LENGTH, TAG_APPLICATION_ID, TAG_NONCE, TAG_PURPOSE]);
        assert_eq!(params[4].bytes, &[9; 12], "the nonce is carried as bytes");
        let unbound = gcm_parameters(&[], &[9; 12]);
        assert!(unbound.iter().all(|p| p.tag != TAG_APPLICATION_ID), "a key bound to nothing names no application");
    }

    /// The note is one structure and the signature over it: the numbers the
    /// secure world wrote and the time, then the signature, which the note
    /// points at from forty bytes in.
    #[test]
    fn a_note_is_carried_as_one_structure_and_its_signature() {
        assert_eq!(NOTE_BYTES, 56);
        assert_eq!(NOTE_POINTER_OFFSET, 40);
        let note = Token {
            challenge: 0x0807_0605_0403_0201,
            user: 0x1817_1615_1413_1211,
            authenticator: 0x2827_2625_2423_2221,
            kind: 1,
            when: 0x3837_3635_3433_3231,
            mac: vec![0xAB; 32],
        };
        let mut call = Message::call(SERVICE);
        write_note(&mut call, Some(&note));
        assert_eq!(call.addresses().len(), 2, "the note, then the signature it points at");
        let mut without = Message::call(SERVICE);
        write_note(&mut without, None);
        assert_eq!(without.addresses().len(), 2, "a note nobody wrote is still a note, all zeroes");
    }
}
