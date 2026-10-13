mod credential;
mod error;
mod keyboard_interactive;

use std::{fmt, path::Path, sync::Arc};

use async_trait::async_trait;
use rshell_core::{AuthenticationKind, ConnectionProfile, TransportKind};
use rshell_storage::CredentialVault;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use secrecy::SecretString;

use credential::{optional_secret, required_secret};
pub use error::AuthPlanError;
pub use keyboard_interactive::{
    KeyboardInteractiveResponseError, keyboard_interactive_request,
    validate_keyboard_interactive_response,
};

/// Authentication material prepared once for a transport. Secret-bearing variants intentionally
/// own their values so native transport can consume them without cloning.
pub enum AuthPlan {
    Password {
        host: String,
        password: SecretString,
    },
    PublicKey {
        host: String,
        identity_file: std::path::PathBuf,
        passphrase: Option<SecretString>,
    },
    Agent {
        host: String,
    },
    KeyboardInteractive {
        host: String,
    },
    /// Public-key authentication with a decoded private key held in memory, for applications
    /// that keep keys somewhere other than files (a keychain). Encrypted keys are decrypted by
    /// the application before the plan is built.
    PrivateKey {
        host: String,
        key: Arc<PrivateKey>,
    },
    /// Public-key authentication whose signature comes from an [`ExternalSigner`] (a hardware
    /// token, a platform authenticator); the private key never enters this process.
    Signer {
        host: String,
        public_key: PublicKey,
        signer: Arc<dyn ExternalSigner>,
    },
}

/// Signs public-key authentication data outside this process.
#[async_trait]
pub trait ExternalSigner: Send + Sync {
    /// Signs `data`, the session data SSH authenticates with. `hash` is the SHA-2 variant chosen
    /// for RSA keys and `None` for other algorithms. Returns the SSH signature blob:
    /// `string(signature algorithm) || string(signature)`, followed by the flags byte and the
    /// counter for `sk-*` keys.
    #[must_use = "签名操作需要等待并检查认证结果"]
    async fn sign(
        &self,
        data: &[u8],
        hash: Option<HashAlg>,
    ) -> Result<Vec<u8>, ExternalSignerError>;
}

/// An external signer could not sign. The reason stays with the application that provided the
/// signer; the transport reports an authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalSignerError;

impl fmt::Display for ExternalSignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("external signer failed")
    }
}

impl std::error::Error for ExternalSignerError {}

impl AuthPlan {
    /// Builds an authentication plan from application-provided material without reading a vault.
    /// The optional secret is moved directly into the selected plan.
    pub fn from_secret(
        profile: &ConnectionProfile,
        secret: Option<SecretString>,
    ) -> Result<Self, AuthPlanError> {
        if !supported_combination(profile.transport, profile.authentication) {
            return Err(AuthPlanError::UnsupportedCombination {
                host: profile.host.clone(),
                transport: profile.transport,
                authentication: profile.authentication,
            });
        }
        let host = profile.host.clone();
        match profile.authentication {
            AuthenticationKind::Password => secret
                .map(|password| Self::Password { host, password })
                .ok_or(AuthPlanError::CredentialMissing {
                    host: profile.host.clone(),
                    authentication: profile.authentication,
                }),
            AuthenticationKind::PublicKey => {
                let identity_file = profile
                    .identity_file
                    .clone()
                    .filter(|path| has_path_text(path))
                    .ok_or(AuthPlanError::MissingIdentityFile {
                        host: host.clone(),
                        authentication: profile.authentication,
                    })?;
                Ok(Self::PublicKey {
                    host,
                    identity_file,
                    passphrase: secret,
                })
            }
            AuthenticationKind::Agent => Ok(Self::Agent { host }),
            AuthenticationKind::KeyboardInteractive => Ok(Self::KeyboardInteractive { host }),
        }
    }

    /// Builds a public-key plan from a private key held in memory; `identity_file` is not read.
    pub fn from_private_key(
        profile: &ConnectionProfile,
        key: Arc<PrivateKey>,
    ) -> Result<Self, AuthPlanError> {
        require_public_key(profile)?;
        Ok(Self::PrivateKey {
            host: profile.host.clone(),
            key,
        })
    }

    /// Builds a public-key plan that signs with an [`ExternalSigner`] holding the private key of
    /// `public_key`; `identity_file` is not read.
    pub fn from_signer(
        profile: &ConnectionProfile,
        public_key: PublicKey,
        signer: Arc<dyn ExternalSigner>,
    ) -> Result<Self, AuthPlanError> {
        require_public_key(profile)?;
        Ok(Self::Signer {
            host: profile.host.clone(),
            public_key,
            signer,
        })
    }

    pub fn from_profile(
        profile: &ConnectionProfile,
        vault: &dyn CredentialVault,
    ) -> Result<Self, AuthPlanError> {
        if !supported_combination(profile.transport, profile.authentication) {
            return Err(AuthPlanError::UnsupportedCombination {
                host: profile.host.clone(),
                transport: profile.transport,
                authentication: profile.authentication,
            });
        }

        let host = profile.host.clone();
        match profile.authentication {
            AuthenticationKind::Password => {
                let password = required_secret(profile, vault)?;
                Ok(Self::Password { host, password })
            }
            AuthenticationKind::PublicKey => {
                let identity_file = profile
                    .identity_file
                    .clone()
                    .filter(|path| has_path_text(path))
                    .ok_or(AuthPlanError::MissingIdentityFile {
                        host: host.clone(),
                        authentication: profile.authentication,
                    })?;
                let passphrase = optional_secret(profile, vault)?;
                Ok(Self::PublicKey {
                    host,
                    identity_file,
                    passphrase,
                })
            }
            AuthenticationKind::Agent => Ok(Self::Agent { host }),
            AuthenticationKind::KeyboardInteractive => Ok(Self::KeyboardInteractive { host }),
        }
    }

    pub fn kind(&self) -> AuthenticationKind {
        match self {
            Self::Password { .. } => AuthenticationKind::Password,
            Self::PublicKey { .. } | Self::PrivateKey { .. } | Self::Signer { .. } => {
                AuthenticationKind::PublicKey
            }
            Self::Agent { .. } => AuthenticationKind::Agent,
            Self::KeyboardInteractive { .. } => AuthenticationKind::KeyboardInteractive,
        }
    }

    pub fn host(&self) -> &str {
        match self {
            Self::Password { host, .. }
            | Self::PublicKey { host, .. }
            | Self::PrivateKey { host, .. }
            | Self::Signer { host, .. }
            | Self::Agent { host }
            | Self::KeyboardInteractive { host } => host,
        }
    }
}

impl fmt::Debug for AuthPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthPlan")
            .field("kind", &self.kind())
            .field("host", &self.host())
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

fn require_public_key(profile: &ConnectionProfile) -> Result<(), AuthPlanError> {
    if profile.authentication != AuthenticationKind::PublicKey
        || !supported_combination(profile.transport, profile.authentication)
    {
        return Err(AuthPlanError::UnsupportedCombination {
            host: profile.host.clone(),
            transport: profile.transport,
            authentication: profile.authentication,
        });
    }
    Ok(())
}

fn supported_combination(transport: TransportKind, authentication: AuthenticationKind) -> bool {
    matches!(
        (transport, authentication),
        (
            TransportKind::SystemOpenSsh,
            AuthenticationKind::Agent | AuthenticationKind::PublicKey
        ) | (
            TransportKind::NativeSsh,
            AuthenticationKind::Password
                | AuthenticationKind::PublicKey
                | AuthenticationKind::Agent
                | AuthenticationKind::KeyboardInteractive
        )
    )
}

fn has_path_text(path: &Path) -> bool {
    path.to_str()
        .map_or(!path.as_os_str().is_empty(), |text| !text.trim().is_empty())
}
