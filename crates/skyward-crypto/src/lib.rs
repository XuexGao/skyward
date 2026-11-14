pub mod encryption;
pub mod fscrypt;
pub mod gatekeeper;
pub mod keystore;
pub mod locksettings;
pub mod sharedsecret;
pub mod token;
pub mod user;
pub mod weaver;

#[cfg(target_os = "android")]
pub mod data;
#[cfg(target_os = "android")]
pub mod keymaster;
#[cfg(target_os = "android")]
pub mod keymint;
#[cfg(target_os = "android")]
pub mod keystore2;

/// The phone's key service, of whichever kind its secure world speaks: the
/// newer `IKeyMintDevice` on phones built from Android 11 on, and the older
/// `IKeymasterDevice` 3.0 on the ones before, as the OPPO R9s and A57.
///
/// A key the service holds is unwrapped by the service itself, under what
/// the key is bound to and, where a screen lock guards it, the note the
/// secure world wrote when that lock was answered. Which kind of service it
/// is changes nothing above this.
#[cfg(target_os = "android")]
pub trait KeyService: keystore::Decryptor {
    /// Turn a key that only the storage hardware can use into the form it
    /// takes for this start of the phone.
    fn ephemeral_storage_key(&self, key: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// Undo an AES-GCM encryption the service did with `key_blob`, taking
    /// the note the secure world wrote where a screen lock guards the key.
    fn gcm_decrypt_with(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        body: &[u8],
        note: Option<&token::Token>,
    ) -> anyhow::Result<Vec<u8>>;

    /// What the phone says about its key hardware, as a line for the log.
    fn described(&self) -> anyhow::Result<String>;
}

#[cfg(target_os = "android")]
impl KeyService for keymint::KeyMint<'_> {
    fn ephemeral_storage_key(&self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        keymint::KeyMint::ephemeral_storage_key(self, key)
    }

    fn gcm_decrypt_with(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        body: &[u8],
        note: Option<&token::Token>,
    ) -> anyhow::Result<Vec<u8>> {
        keymint::KeyMint::gcm_decrypt(self, key_blob, app_id, nonce, body, note)
    }

    fn described(&self) -> anyhow::Result<String> {
        let h = self.hardware()?;
        Ok(format!("keymint {}, security level {}, {}", h.version, h.security_level, h.name))
    }
}

#[cfg(target_os = "android")]
impl KeyService for keymaster::Keymaster<'_> {
    /// The older key service hands a storage key back as it holds it; there
    /// is no second form of it to make.
    fn ephemeral_storage_key(&self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(key.to_vec())
    }

    fn gcm_decrypt_with(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        body: &[u8],
        note: Option<&token::Token>,
    ) -> anyhow::Result<Vec<u8>> {
        keymaster::Keymaster::gcm_decrypt(self, key_blob, app_id, nonce, body, note)
    }

    fn described(&self) -> anyhow::Result<String> {
        let f = self.features()?;
        Ok(format!("keymaster 3.0, version {}, security level {}, {} kinds of key", f.version, f.security_level, f.algorithms.len()))
    }
}

#[cfg(target_os = "android")]
impl keystore::Decryptor for keymint::KeyMint<'_> {
    fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> anyhow::Result<Vec<u8>> {
        // The keys unwrapped this way belong to the phone rather than to
        // any user, so none of them is guarded by a screen lock.
        keymint::KeyMint::gcm_decrypt(self, key_blob, app_id, nonce, body, None)
    }
}

#[cfg(target_os = "android")]
impl keystore::Decryptor for keymaster::Keymaster<'_> {
    fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> anyhow::Result<Vec<u8>> {
        keymaster::Keymaster::gcm_decrypt(self, key_blob, app_id, nonce, body, None)
    }
}
