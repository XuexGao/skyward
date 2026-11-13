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
const TAG_AUTH_TOKEN: u32 = KIND_BYTES | 1002;
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
        let mut out = Vec::new();
        // What the key may be used for comes as one structure holding two
        // lists: what software checks, and what the secure world checks.
        let end = read.structure().context("read what the key may be used for")?;
        for _ in 0..2 {
            out.extend(read.parameters().context("read what the key may be used for")?);
        }
        read.go(end).context("step to the end of what the key may be used for")?;
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
        let params = [(TAG_APPLICATION_ID, Value::Bytes(app_id))];
        write_parameters(&mut call, &params);
        let reply = self.device.transact(UPGRADE_KEY, &call).context("renew the key")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("renew the key")?;
        Ok(read.pointed().context("read the renewed key")?.to_vec())
    }

    /// Open a decryption with the key service and keep hold of it.
    fn begin(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], note: Option<&Token>) -> Result<Handle<'a>> {
        let token = note.map(token_bytes);
        let mut params = vec![
            (TAG_BLOCK_MODE, Value::Enum(BLOCK_MODE_GCM)),
            (TAG_PADDING, Value::Enum(PADDING_NONE)),
            (TAG_MAC_LENGTH, Value::Uint(GCM_TAG_BITS)),
        ];
        if !app_id.is_empty() {
            params.push((TAG_APPLICATION_ID, Value::Bytes(app_id)));
        }
        params.push((TAG_NONCE, Value::Bytes(nonce)));
        // A key guarded by the screen lock takes the note the secure world
        // wrote when it was answered; one that is not guarded takes none.
        if let Some(token) = &token {
            params.push((TAG_AUTH_TOKEN, Value::Bytes(token)));
        }
        params.push((TAG_PURPOSE, Value::Enum(PURPOSE_DECRYPT)));

        let mut call = Message::call(SERVICE);
        call.u32(PURPOSE_DECRYPT);
        call.bytes(key_blob);
        write_parameters(&mut call, &params);

        // The decryption the service opens outlives the reply that named
        // it, so take a share of it before the reply's room goes back.
        let reply = self.device.transact(BEGIN, &call).context("start a decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("start a decryption")?;
        let end = read.structure().context("read what the key service answered")?;
        read.parameters().context("read how the decryption is set up")?;
        read.go(end).context("step to the end of what the key service answered")?;
        let handle = read.number().context("read the decryption the key service opened")?;
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
        let reply = operation.transact(UPDATE, &call).context("feed the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("feed the decryption")?;
        let taken = read.count().context("read how much the decryption took")?;
        if taken as usize != input.len() {
            bail!("the decryption took {taken} of the {} bytes it was given", input.len());
        }
        let end = read.structure().context("read how the decryption is set up")?;
        read.go(end).context("step to the end of what the decryption answered")?;
        Ok(read.pointed().context("read what the decryption gave back")?.to_vec())
    }

    fn finish(&self, operation: &Handle) -> Result<Vec<u8>> {
        let mut call = Message::call(SERVICE);
        call.u64(operation.number() as u64);
        write_parameters(&mut call, &[]);
        call.bytes(&[]);
        call.bytes(&[]);
        let reply = operation.transact(FINISH, &call).context("close the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("close the decryption, which is where a wrong key is refused")?;
        let end = read.structure().context("read how the decryption is set up")?;
        read.go(end).context("step to the end of what the decryption answered")?;
        Ok(read.pointed().context("read what the decryption ended with")?.to_vec())
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
        Answer::new(reply.bytes()).status().context("drop the decryption")
    }
}

/// What a parameter carries. The kind of value it is decides which arm the
/// interface's union writes.
#[derive(Clone, Copy)]
enum Value<'a> {
    Enum(u32),
    Uint(u32),
    Bytes(&'a [u8]),
}

/// Write a list of parameters: how many there are, then each as a structure
/// of its own, so that the far side can step over what it does not know.
fn write_parameters(call: &mut Message, params: &[(u32, Value<'_>)]) {
    call.u32(params.len() as u32);
    for (tag, value) in params {
        let at = call.mark();
        call.u32(0);
        call.u32(*tag);
        match value {
            Value::Enum(v) | Value::Uint(v) => call.u32(*v),
            Value::Bytes(b) => call.bytes(b),
        }
        call.fill(at);
    }
}

/// The note the secure world wrote, as the older interface takes it: the
/// numbers it says, then the time as a structure of its own, then the
/// signature over all of it.
fn token_bytes(note: &Token) -> Vec<u8> {
    // The note is the secure world's own structure, read the same way
    // whether it is checked or handed over: the first three numbers in the
    // order this machine uses, and the kind of answer and the time in the
    // order the network uses. It is packed, so nothing is padded, and the
    // fields follow one another exactly.
    let mut out = Vec::new();
    out.push(0u8);
    out.extend_from_slice(&note.challenge.to_le_bytes());
    out.extend_from_slice(&note.user.to_le_bytes());
    out.extend_from_slice(&note.authenticator.to_le_bytes());
    out.extend_from_slice(&(note.kind as u32).to_be_bytes());
    out.extend_from_slice(&note.when.to_be_bytes());
    out.extend_from_slice(&note.mac);
    out
}

/// The number a tag carries, without the kind of value it is.
#[allow(dead_code)]
pub fn tag_number(tag: u32) -> u32 {
    tag & TAG_NUMBER
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(TAG_AUTH_TOKEN, 0x9000_03ea);
        for tag in [TAG_PURPOSE, TAG_BLOCK_MODE, TAG_PADDING, TAG_MAC_LENGTH, TAG_APPLICATION_ID, TAG_NONCE, TAG_AUTH_TOKEN] {
            assert_eq!(tag_number(tag), tag & 0x0fff_ffff, "the number it carries, without its kind");
        }
    }

    /// A parameter is written as a structure of its own, so the far side can
    /// step over one it does not know: that it is there, how long its own
    /// fields are, the tag, and the value.
    #[test]
    fn a_parameter_is_written_as_a_structure_of_its_own() {
        let mut call = Message::call(SERVICE);
        write_parameters(&mut call, &[(TAG_BLOCK_MODE, Value::Enum(BLOCK_MODE_GCM))]);
        let values = call.values();
        let at = SERVICE.len() + 1;
        let at = at.div_ceil(4) * 4;
        assert_eq!(u32::from_le_bytes(values[at..at + 4].try_into().unwrap()), 1, "one parameter");
        assert_eq!(u32::from_le_bytes(values[at + 4..at + 8].try_into().unwrap()), 1, "it is there");
        assert_eq!(u32::from_le_bytes(values[at + 8..at + 12].try_into().unwrap()), 8, "its own fields are two words");
        assert_eq!(u32::from_le_bytes(values[at + 12..at + 16].try_into().unwrap()), TAG_BLOCK_MODE);
        assert_eq!(u32::from_le_bytes(values[at + 16..at + 20].try_into().unwrap()), BLOCK_MODE_GCM);
    }

    /// The note is the secure world's own packed structure, and the key
    /// service checks its signature over exactly these bytes: the version,
    /// three numbers in this machine's order, the kind of answer and the
    /// time in the network's order, then the signature. Nothing is padded.
    #[test]
    fn a_note_is_written_as_the_secure_world_holds_it() {
        let note = Token {
            challenge: 0x0807_0605_0403_0201,
            user: 0x1817_1615_1413_1211,
            authenticator: 0x2827_2625_2423_2221,
            kind: 1,
            when: 0x3837_3635_3433_3231,
            mac: vec![0xAB; 32],
        };
        let raw = token_bytes(&note);
        assert_eq!(raw.len(), 1 + 8 + 8 + 8 + 4 + 8 + 32, "packed, and no room taken before anything");
        assert_eq!(raw[0], 0, "the only layout there is");
        assert_eq!(u64::from_le_bytes(raw[1..9].try_into().unwrap()), note.challenge, "in this machine's order");
        assert_eq!(u64::from_le_bytes(raw[9..17].try_into().unwrap()), note.user);
        assert_eq!(u64::from_le_bytes(raw[17..25].try_into().unwrap()), note.authenticator);
        assert_eq!(u32::from_be_bytes(raw[25..29].try_into().unwrap()), 1, "the kind of answer, in the network's order");
        assert_eq!(u64::from_be_bytes(raw[29..37].try_into().unwrap()), note.when, "and so is the time");
        assert_eq!(&raw[37..], &[0xAB; 32]);
    }

    /// What is written is what is read back: the two halves of the note
    /// agree, so a note taken from the credential service is handed to the
    /// key service unchanged.
    #[test]
    fn a_note_read_from_the_credential_service_is_written_out_as_it_came() {
        let raw: Vec<u8> = [
            vec![0u8],
            7i64.to_le_bytes().to_vec(),
            0x253c_22c3_acbb_a741u64.to_le_bytes().to_vec(),
            9i64.to_le_bytes().to_vec(),
            1i32.to_be_bytes().to_vec(),
            1_700_000_000i64.to_be_bytes().to_vec(),
            vec![0x5A; 32],
        ]
        .concat();
        let note = Token::of(&raw).expect("a note the secure world wrote");
        assert_eq!(token_bytes(&note), raw, "handed over byte for byte");
    }
}
