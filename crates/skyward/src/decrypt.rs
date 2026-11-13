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

