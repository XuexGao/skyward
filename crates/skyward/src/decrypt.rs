//! Opening the data partition and its users' own files on a thread of its
//! own, so the screen keeps up: the keys come from the secure world, and
//! what a user enters at their screen lock is checked slowly on purpose.

use anyhow::{Context, Result};
use skyward_binder::driver::Binder;
use skyward_crypto::data::{self, Closed, Opening};
use skyward_crypto::keymint::KeyMint;
use skyward_crypto::keymaster::Keymaster;
use skyward_crypto::KeyService;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};

pub enum Job {
    /// Open the partition as far as it opens with nothing a user knows.
    Open,
    /// Open the own files of `user` with what they entered at their screen
    /// lock; `closed` are the users whose own files are still closed.
    Unlock { closed: Vec<Closed>, user: u32, credential: Vec<u8> },
}

/// How a job ended: what it opened, or why it did not.
pub enum Ended {
    Opened(Result<Opening, String>),
    Unlocked(Result<Vec<Closed>, String>),
}

pub struct Decryptor {
    ended: Receiver<Ended>,
    /// Readable once the job has ended.
    wake: OwnedFd,
    thread: Option<JoinHandle<()>>,
}

impl Decryptor {
    pub fn start(job: Job) -> Result<Decryptor> {
        let mut fds = [0; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(std::io::Error::last_os_error()).context("make the decrypting thread's wake pipe");
        }
        let (wake, signal) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let (tx, ended) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("decrypt".into())
            .spawn(move || {
                let ended_as = match job {
                    Job::Open => Ended::Opened(with_key_service(data::open_without_credential)),
                    Job::Unlock { closed, user, credential } => {
                        Ended::Unlocked(with_key_service(|service| data::unlock(service, &closed, user, &credential)))
                    }
                };
                // The screen only stops listening once it has let the
                // thread go.
                let _ = tx.send(ended_as);
                unsafe { libc::write(signal.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
            })
            .context("start the decrypting thread")?;
        Ok(Decryptor { ended, wake, thread: Some(thread) })
    }

    pub fn fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    /// How the job ended, once it has.
    pub fn ended(&self) -> Option<Ended> {
        let mut drain = [0u8; 8];
        while unsafe { libc::read(self.wake.as_raw_fd(), drain.as_mut_ptr().cast(), drain.len()) } > 0 {}
        self.ended.try_recv().ok()
    }
}

impl Drop for Decryptor {
    /// The screen lets the thread go once its job has ended.
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the decrypting thread does not panic");
        }
    }
}

/// Do `work` with the phone's key service, reached afresh for it, and say
/// why it failed in words for the page.
///
/// A phone built from Android 11 on serves the newer `IKeyMintDevice`, and
/// one built before it serves the older `IKeymasterDevice` 3.0, as the OPPO
/// R9s and A57 do. Which one it is decides which driver the service is
/// reached over, so the newer is tried first and the older after it.
///
/// Being registered is not the same as answering: a phone whose secure world
/// only speaks the older interface can still have something registered under
/// the newer one's name, put there to translate between them, and that
/// translation is what a recovery has none of. So each is asked something
/// that changes nothing before its answer is used, and one that does not
/// answer is passed over for the next.
pub fn with_key_service<T>(work: impl FnOnce(&dyn KeyService) -> Result<T>) -> Result<T, String> {
    let done = try_key_services(work);
    done.map_err(|e| format!("{e:#}"))
}

/// Do `work` with the first key service that answers: the newer kind, then
/// the older.
///
/// A handle borrows the driver it was reached through, so each attempt keeps
/// both for as long as it uses them, and the work is handed over only once a
/// service has answered something that changes nothing.
fn try_key_services<T>(work: impl FnOnce(&dyn KeyService) -> Result<T>) -> Result<T> {
    let mut work = Some(work);
    let mut refusals = Vec::new();
    if let Ok(binder) = Binder::open() {
        if let Ok(service) = KeyMint::open(&binder) {
            if service.hardware().context("ask the newer key service about itself").is_ok() {
                return (work.take().expect("the work is done once"))(&service);
            }
            refusals.push("the newer key service: it did not say what it is".to_string());
        } else {
            refusals.push(format!("the newer key service: {SERVICE_NEWER} is not running"));
        }
    } else {
        refusals.push("the newer key service: the driver it is reached over is not here".to_string());
    }
    match Binder::hardware() {
        Ok(hardware) => match Keymaster::open(&hardware) {
            Ok(service) => match service.features() {
                Ok(_) => (work.take().expect("the work is done once"))(&service),
                Err(e) => anyhow::bail!("no key service answered; {}; the older one: {e:#}", refusals.join("; ")),
            },
            Err(e) => anyhow::bail!("no key service answered; {}; the older one: {e:#}", refusals.join("; ")),
        },
        Err(e) => anyhow::bail!(
            "no key service answered; {}; the older one, over the hardware driver: {e:#}",
            refusals.join("; ")
        ),
    }
}

/// The name the newer key service registers under, for the log.
const SERVICE_NEWER: &str = skyward_crypto::keymint::SERVICE;

/// Which key service the phone serves, for the kernel log: the newer kind,
/// the older kind, or why neither answered.
pub fn key_service() -> Result<String, String> {
    with_key_service(|service| service.described())
}


/// Say how far opening the data partition gets, step by step, without
/// changing anything, so that a phone whose data does not open says where
/// it stops rather than only that it did.
///
/// Every step reports what it found and why it could not go on, and the
/// work goes on to the next step where one fails: the point is to see all
/// of it at once on a phone with no keyboard to type at.
#[cfg(target_os = "android")]
pub fn report(credential: Option<&str>, user: u32, clean: bool) -> Result<()> {
    use skyward_crypto::data;
    let say = |step: &str, done: Result<String>| {
        match done {
            Ok(said) => println!("{step}: {said}"),
            Err(e) => println!("{step}: no, {e:#}"),
        }
    };
    let table = skyward_block::fstab::read(data::MOUNT);
    let entries = match &table {
        Ok(entries) => entries,
        Err(e) => {
            println!("the phone's table for /data: no, {e:#}");
            return Ok(());
        }
    };
    for e in entries {
        println!("the phone's table for /data: {} -> {} {}", e.device, e.mount_point, e.filesystem);
        println!("  options {:?}, flags {:?}", e.options, e.extras);
    }
    if entries.is_empty() {
        println!("the phone's table for /data: says nothing");
        return Ok(());
    }
    say("the key service", key_service().map_err(anyhow::Error::msg));
    say(
        "how the partition is encrypted whole",
        (|| -> Result<String> {
            let entry = entries.first().context("no entry")?;
            Ok(match skyward_crypto::data::Encryption::of(entry)? {
                Some(e) => format!("{}, keys the hardware holds: {}", e.cipher, e.wrapped),
                None => "not at all: each user's files are encrypted instead".to_string(),
            })
        })(),
    );
    for probe in ["/data/misc", "/data/system", "/data/data"] {
        say(
            &format!("the policy of {probe}"),
            skyward_crypto::fscrypt::policy_of(std::path::Path::new(probe)).map(|p| match p {
                Some(p) => format!("version {}, descriptor {:?}", p.version, p.descriptor),
                None => "none of its own".to_string(),
            }).map_err(anyhow::Error::from),
        );
    }
    let mode = std::fs::read_to_string("/data/unencrypted/mode");
    say("the mode of the shared key", mode.as_ref().map(|m| m.trim().to_string()).map_err(|e| anyhow::anyhow!("{e}")));
    for (what, path) in [
        ("the shared key", "/data/unencrypted/key"),
        ("the shared key's name", "/data/unencrypted/ref"),
        ("the key store", skyward_crypto::keystore2::DATABASE),
        ("the lock settings", skyward_crypto::locksettings::DATABASE),
    ] {
        say(what, std::fs::metadata(path).map(|m| format!("{} bytes", m.len())).map_err(|e| anyhow::anyhow!("{path}: {e}")));
    }
    let mut users = Vec::new();
    for dir in ["/data/misc/vold/user_keys/de", "/data/misc/vold/user_keys/ce"] {
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                let names: Vec<String> = entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
                say(dir, Ok(format!("{names:?}")));
                if dir.ends_with("/de") {
                    users = names.iter().filter_map(|n| n.parse::<u32>().ok()).collect();
                }
            }
            Err(e) => say(dir, Err(anyhow::anyhow!("{e}"))),
        }
    }
    if users.is_empty() {
        println!("then: no user's keys are on the partition; there is nothing to open");
        return Ok(());
    }
    let opened = with_key_service(|service| skyward_crypto::data::open_without_credential(service));
    match &opened {
        Ok(o) => {
            println!(
                "then: /data {} , closed users {:?}",
                if o.mounted.is_some() { "opened" } else { "was open already" },
                o.closed
            );
        }
        Err(e) => println!("then: /data did not open: {e}"),
    }
    if let Some(credential) = credential {
        match &opened {
            Ok(o) => match with_key_service(|service| skyward_crypto::data::unlock(service, &o.closed, user, credential.as_bytes())) {
                Ok(still) => println!("then: after the credential of user {user}, still closed {still:?}"),
                Err(e) => println!("then: the credential of user {user} did not open their files: {e}"),
            },
            Err(_) => println!("then: the credential was not tried, the partition did not open"),
        }
    }
    if clean {
        if let Err(e) = skyward_crypto::data::close() {
            println!("then: closing left something behind: {e:#}");
        } else {
            println!("then: closed again, as it was found");
        }
    }
    Ok(())
}
