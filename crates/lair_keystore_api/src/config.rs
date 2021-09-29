//! Lair Configuration Types

use crate::prelude::*;
use std::future::Future;
use std::sync::Arc;

/// Enum for configuring signature fallback handling
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum LairServerSignatureFallback {
    /// No fallback handling. If a pub key does not exist
    /// in the lair store, a sign_by_pub_key request will error.
    None,

    /// Specify a command to execute on lair server start.
    /// This command will be fed framed json signature requests on stdin,
    /// and is expected to respond to those requests with framed
    /// json responses on stdout.
    #[serde(rename_all = "camelCase")]
    Command {
        /// The program command to execute.
        program: std::path::PathBuf,

        /// Optional arguments to be passed to command on execute.
        args: Option<Vec<String>>,
    },
}

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

    /// Configuration for managing sign_by_pub_key fallback
    /// in case the pub key does not exist in the lair store.
    pub signature_fallback: LairServerSignatureFallback,

    /// salt for decrypting runtime data
    pub runtime_secrets_salt: BinDataSized<16>,

    /// argon2id mem_limit for decrypting runtime data
    pub runtime_secrets_mem_limit: u32,

    /// argon2id ops_limit for decrypting runtime data
    pub runtime_secrets_ops_limit: u32,

    /// the runtime context key secret
    pub runtime_secrets_context_key: SecretDataSized<32, 49>,

    /// the server identity signature keypair seed
    pub runtime_secrets_id_seed: SecretDataSized<32, 49>,
}

impl std::fmt::Display for LairServerConfigInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_yaml::to_string(&self).map_err(|_| std::fmt::Error)?;

        // inject some helpful comments
        let mut lines = Vec::new();
        for (id, line) in s.split('\n').enumerate() {
            if id > 0 {
                if line.starts_with("connectionUrl:") {
                    lines.push("");
                    lines.push("# The connection url for communications between server / client.");
                    lines.push("# - `unix:///path/to/unix/socket?k=Yada`");
                    lines.push(
                        "# - `named_pipe:\\\\.\\pipe\\my_pipe_name?k=Yada`",
                    );
                    lines.push("# - (not yet supported) `tcp://127.0.0.1:12345?k=Yada`");
                } else if line.starts_with("pidFile:") {
                    lines.push("");
                    lines.push("# The pid file for managing a running lair-keystore process");
                } else if line.starts_with("storeFile:") {
                    lines.push("");
                    lines.push(
                        "# The sqlcipher store file for persisting secrets",
                    );
                } else if line.starts_with("signatureFallback:") {
                    lines.push("");
                    lines.push(
                        "# Configuration for managing sign_by_pub_key fallback",
                    );
                    lines.push("# in case the pub key does not exist in the lair store.");
                    lines.push("# - `signatureFallback: none`");
                    lines.push("# - ```");
                    lines.push("#   signatureFallback:");
                    lines.push("#     command:");
                    lines.push("#       # 'program' will resolve to a path, specifying 'echo'");
                    lines.push("#       # will try to run './echo', probably not what you want.");
                    lines.push("#       program: \"./my-executable\"");
                    lines.push("#       # args are optional");
                    lines.push("#       args:");
                    lines.push("#         - test-arg1");
                    lines.push("#         - test-arg2");
                    lines.push("#   ```");
                } else if line.starts_with("runtimeSecretsSalt:") {
                    lines.push("");
                    lines.push("# -- cryptographic secrets --");
                    lines.push("# If you modify the data below, you risk loosing access to your keys.");
                }
            }
            lines.push(line);
        }
        f.write_str(&lines.join("\n"))
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
            // default pid_file name is '[root_path]/pid_file'
            let mut pid_file = root_path.clone();
            pid_file.push("pid_file");

            // default store_file name is '[root_path]/store_file'
            let mut store_file = root_path.clone();
            store_file.push("store_file");

            // generate a random salt for the pwhash
            let salt = <sodoken::BufWriteSized<16>>::new_no_lock();
            sodoken::random::bytes_buf(salt.clone()).await?;

            // pull the captured argon2id limits
            let ops_limit = limits.as_ops_limit();
            let mem_limit = limits.as_mem_limit();

            // generate an argon2id pre_secret from the passphrase
            let pre_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::hash::argon2id::hash(
                pre_secret.clone(),
                passphrase,
                salt.clone(),
                ops_limit,
                mem_limit,
            )
            .await?;

            // derive our context secret
            // this will be used to encrypt the context_key
            let ctx_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::kdf::derive_from_key(
                ctx_secret.clone(),
                42,
                *b"CtxSecKy",
                pre_secret.clone(),
            )?;

            // derive our signature secret
            // this will be used to encrypt the signature seed
            let id_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::kdf::derive_from_key(
                id_secret.clone(),
                142,
                *b"IdnSecKy",
                pre_secret,
            )?;

            // the context key is used to encrypt our store_file
            let context_key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::random::bytes_buf(context_key.clone()).await?;

            // the sign seed derives our signature keypair
            // which allows us to authenticate server identity
            let id_seed = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::random::bytes_buf(id_seed.clone()).await?;

            // server identity encryption keypair
            let id_pk = <sodoken::BufWriteSized<32>>::new_no_lock();
            let id_sk = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            use sodoken::crypto_box::curve25519xchacha20poly1305::*;
            seed_keypair(id_pk.clone(), id_sk, id_seed.clone()).await?;

            // lock the context key
            let context_key = SecretDataSized::encrypt(
                ctx_secret.to_read_sized(),
                context_key.to_read_sized(),
            )
            .await?;

            // lock the signature seed
            let id_seed = SecretDataSized::encrypt(
                id_secret.to_read_sized(),
                id_seed.to_read_sized(),
            )
            .await?;

            // get the signature public key bytes for encoding in the url
            let id_pk: BinDataSized<32> =
                id_pk.try_unwrap_sized().unwrap().into();

            // on windows, we default to using "named pipes"
            #[cfg(windows)]
            let connection_url = {
                let id = nanoid::nanoid!();
                url::Url::parse(&format!(
                    "named-pipe:\\\\.\\pipe\\{}?k={}",
                    id, id_pk
                ))
                .unwrap()
            };

            // on not-windows, we default to using unix domain sockets
            #[cfg(not(windows))]
            let connection_url = {
                let mut con_path = root_path.clone();
                con_path.push("socket");
                url::Url::parse(&format!(
                    "unix://{}?k={}",
                    con_path.to_str().unwrap(),
                    id_pk
                ))
                .unwrap()
            };

            // put together the full server config struct
            let config = LairServerConfigInner {
                connection_url,
                pid_file,
                store_file,
                signature_fallback: LairServerSignatureFallback::None,
                runtime_secrets_salt: salt.try_unwrap_sized().unwrap().into(),
                runtime_secrets_mem_limit: mem_limit,
                runtime_secrets_ops_limit: ops_limit,
                runtime_secrets_context_key: context_key,
                runtime_secrets_id_seed: id_seed,
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

/// Configuration for running a lair-keystore server instance.
pub type LairServerConfig = Arc<LairServerConfigInner>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_config_yaml() {
        let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);
        let mut srv = hc_seed_bundle::PwHashLimits::Interactive
            .with_exec(|| {
                LairServerConfigInner::new("/tmp/my/path", passphrase)
            })
            .await
            .unwrap();

        println!("-- server config start --");
        println!("{}", &srv);
        println!("-- server config end --");
        assert_eq!(
            std::path::PathBuf::from("/tmp/my/path").as_path(),
            srv.pid_file.parent().unwrap(),
        );

        srv.signature_fallback = LairServerSignatureFallback::Command {
            program: std::path::Path::new("./my-executable").into(),
            args: Some(vec!["test-arg1".into(), "test-arg2".into()]),
        };

        println!("-- server config start --");
        println!("{}", &srv);
        println!("-- server config end --");
    }
}
