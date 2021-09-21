//! Lair Configuration Types

use crate::prelude::*;
use std::future::Future;
use std::sync::Arc;

/// Config used by lair servers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairServerConfigInner {
    /// The connection url for communications between server / client.
    /// - `unix:///path/to/unix/socket?k=Yada`
    /// - `named_pipe:\\.\pipe\my_pipe_name?k=Yada`
    /// - `tcp://127.0.0.1:12345?k=Yada`
    pub connection_url: url::Url,

    /// The pid file for managing a running lair-keystore process
    pub pid_file: std::path::PathBuf,

    /// The sqlcipher store file for persisting secrets
    pub store_file: std::path::PathBuf,

    /// salt for decrypting runtime data
    pub runtime_secrets_salt: BinDataSized<16>,

    /// argon2id mem_limit for decrypting runtime data
    pub runtime_secrets_mem_limit: u32,

    /// argon2id ops_limit for decrypting runtime data
    pub runtime_secrets_ops_limit: u32,

    /// the runtime context key secret
    pub runtime_secrets_context_key: SecretDataSized<32, 49>,

    /// the server identity signature keypair seed
    pub runtime_secrets_sign_seed: SecretDataSized<32, 49>,
}

impl std::fmt::Display for LairServerConfigInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_yaml::to_string(&self).map_err(|_| std::fmt::Error)?;
        f.write_str(&s)
    }
}

impl LairServerConfigInner {
    /// decode yaml bytes into a config struct
    pub fn from_bytes(bytes: &[u8]) -> LairResult<Self> {
        serde_yaml::from_slice(bytes).map_err(one_err::OneErr::new)
    }

    /// Construct a new default lair server config instance.
    /// Respects hc_seed_bundle::PwHashLimits.
    pub fn new<P>(
        root_path: P,
        passphrase: sodoken::BufRead,
    ) -> impl Future<Output = LairResult<Self>> + 'static + Send
    where
        P: AsRef<std::path::Path>,
    {
        let root_path = root_path.as_ref().to_owned();
        let limits = hc_seed_bundle::PwHashLimits::current();
        async move {
            let mut pid_file = root_path.clone();
            pid_file.push("pid_file");

            let mut store_file = root_path.clone();
            store_file.push("store_file");

            let salt = <sodoken::BufWriteSized<16>>::new_no_lock();
            sodoken::random::bytes_buf(salt.clone()).await?;

            let ops_limit = limits.as_ops_limit();
            let mem_limit = limits.as_mem_limit();

            let pre_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::hash::argon2id::hash(
                pre_secret.clone(),
                passphrase,
                salt.clone(),
                ops_limit,
                mem_limit,
            )
            .await?;

            let ctx_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::kdf::derive_from_key(
                ctx_secret.clone(),
                42,
                *b"CtxSecKy",
                pre_secret.clone(),
            )?;

            let sig_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::kdf::derive_from_key(
                sig_secret.clone(),
                142,
                *b"SigSecKy",
                pre_secret,
            )?;

            let context_key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::random::bytes_buf(context_key.clone()).await?;

            let sign_seed = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::random::bytes_buf(sign_seed.clone()).await?;

            let sign_pk = <sodoken::BufWriteSized<32>>::new_no_lock();
            let sign_sk = <sodoken::BufWriteSized<64>>::new_mem_locked()?;
            sodoken::sign::seed_keypair(
                sign_pk.clone(),
                sign_sk,
                sign_seed.clone(),
            )
            .await?;

            let context_key = SecretDataSized::encrypt(
                ctx_secret.to_read_sized(),
                context_key.to_read_sized(),
            )
            .await?;
            let sign_seed = SecretDataSized::encrypt(
                sig_secret.to_read_sized(),
                sign_seed.to_read_sized(),
            )
            .await?;

            let sign_pk: BinDataSized<32> =
                sign_pk.try_unwrap_sized().unwrap().into();

            #[cfg(windows)]
            let connection_url = {
                let id = nanoid::nanoid!();
                url::Url::parse(&format!(
                    "named-pipe:\\\\.\\pipe\\{}?k={}",
                    id, sign_pk
                ))
                .unwrap()
            };
            // for named pipe: println!("URL PART: {}", connection_url.path());

            #[cfg(not(windows))]
            let connection_url = {
                let mut con_path = root_path.clone();
                con_path.push("socket");
                url::Url::parse(&format!(
                    "unix://{}?k={}",
                    con_path.to_str().unwrap(),
                    sign_pk
                ))
                .unwrap()
            };

            let config = LairServerConfigInner {
                connection_url,
                pid_file,
                store_file,
                runtime_secrets_salt: salt.try_unwrap_sized().unwrap().into(),
                runtime_secrets_mem_limit: mem_limit,
                runtime_secrets_ops_limit: ops_limit,
                runtime_secrets_context_key: context_key,
                runtime_secrets_sign_seed: sign_seed,
            };

            Ok(config)
        }
    }

    /// Get the connection "scheme". i.e. "unix", "named-pipe", or "tcp".
    pub fn get_connection_scheme(&self) -> &str {
        self.connection_url.scheme()
    }

    /// Get the connection "path". This could have different meanings
    /// depending on if we are a unix domain socket or named pipe, etc.
    pub fn get_connection_path(&self) -> &str {
        self.connection_url.path()
    }

    /// Get the server pub key BinDataSized<32> bytes from the connectionUrl
    pub fn get_server_pub_key(&self) -> LairResult<BinDataSized<32>> {
        get_server_pub_key_from_connection_url(&self.connection_url)
    }
}

/// extract a server_pub_key from a connection_url
pub fn get_server_pub_key_from_connection_url(
    url: &url::Url,
) -> LairResult<BinDataSized<32>> {
    for (k, v) in url.query_pairs() {
        if k == "k" {
            let tmp =
                base64::decode_config(v.as_bytes(), base64::URL_SAFE_NO_PAD)
                    .map_err(one_err::OneErr::new)?;
            if tmp.len() != 32 {
                return Err(format!(
                    "invalid server_pub_key len, expected 32, got {}",
                    tmp.len()
                )
                .into());
            }
            let mut out = [0; 32];
            out.copy_from_slice(&tmp);
            return Ok(out.into());
        }
    }
    Err("no server_pub_key on connection_url".into())
}

/// Additional config used by lair servers.
pub type LairServerConfig = Arc<LairServerConfigInner>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_config_yaml() {
        let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);
        let srv = LairServerConfigInner::new("/tmp/my/path", passphrase)
            .await
            .unwrap();
        println!("-- server config start --");
        println!("{}", serde_yaml::to_string(&srv).unwrap());
        println!("-- server config end --");
    }
}
