use std::sync::Arc;
use lair_keystore_api::dependencies::*;
use lair_keystore_api::prelude::*;
use lair_keystore_api::*;
use clap::Parser;

fn vec_to_locked(mut pass_tmp: Vec<u8>) -> LairResult<sodoken::BufRead> {
    match sodoken::BufWrite::new_mem_locked(pass_tmp.len()) {
        Err(e) => {
            pass_tmp.fill(0);
            Err(e)
        }
        Ok(p) => {
            {
                let mut lock = p.write_lock();
                lock.copy_from_slice(&pass_tmp);
                pass_tmp.fill(0);
            }
            Ok(p.to_read())
        }
    }
}

#[allow(clippy::len_zero)]
pub(crate) async fn read_piped_passphrase() -> LairResult<sodoken::BufRead> {
    let mut stdin = tokio::io::stdin();
    let mut pass_tmp = Vec::new();

    use tokio::io::AsyncReadExt;
    stdin.read_to_end(&mut pass_tmp).await?;

    if pass_tmp.len() >= 2
        && pass_tmp[pass_tmp.len() - 1] == 10
        && pass_tmp[pass_tmp.len() - 2] == 13
    {
        pass_tmp.pop();
        pass_tmp.pop();
    } else if pass_tmp.len() >= 1 && pass_tmp[pass_tmp.len() - 1] == 10 {
        pass_tmp.pop();
    }
    vec_to_locked(pass_tmp)
}

#[derive(clap::Parser, Debug)]
#[command(version, about)]
enum Args {
    /// Hash a "SeedString" to create a seed, import it to lair.
    ImportSeedString {
        /// The lair connection url into which we should import the seed.
        connection_url: String,

        /// The "SeedString" to hash / import.
        seed_string: String,
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(err) = main_err().await {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

const SEED_IMPORT: &str = "__seed_import";

async fn main_err() -> LairResult<()> {
    let args = Args::parse();

    let passphrase = read_piped_passphrase().await?;

    match args {
        Args::ImportSeedString {
            connection_url,
            seed_string,
        } => {
            let seed = <sodoken::BufWriteSized<32>>::new_no_lock();
            sodoken::hash::blake2b::hash(
                seed.clone(),
                seed_string.into_bytes(),
            ).await?;

            let pk = <sodoken::BufWriteSized<32>>::new_no_lock();
            let sk = <sodoken::BufWriteSized<64>>::new_mem_locked()?;
            sodoken::sign::seed_keypair(pk.clone(), sk, seed.clone()).await?;

            let client = ipc_keystore_connect(url::Url::parse(&connection_url).unwrap(), passphrase).await?;

            let pk = BinDataSized(Arc::new(*pk.read_lock_sized()));
            if let Ok(_) = client.sign_by_pub_key(pk.clone(), None, Arc::new([0])).await {
                println!("Imported: {:?}", pk);
                return Ok(());
            }

            let seed = seed.to_read_sized();

            let seed_import: Arc<str> = SEED_IMPORT.to_string().into_boxed_str().into();

            let _ = client.new_seed(seed_import.clone(), None, false).await;

            let pk_imp = match client.get_entry(seed_import.clone()).await? {
                LairEntryInfo::Seed { seed_info, .. } => {
                    seed_info.x25519_pub_key
                }
                _ => return Err("invalid entry type".into()),
            };

            let (nonce, cipher) = client.crypto_box_xsalsa_by_pub_key(
                pk_imp.clone(),
                pk_imp.clone(),
                None,
                seed.read_lock().to_vec().into_boxed_slice().into(),
            ).await?;

            let seed_info = client.import_seed(pk_imp.clone(), pk_imp, None, nonce, cipher, rand_utf8::rand_utf8(&mut rand::thread_rng(), 32).into(), false).await?;

            println!("Imported: {:?}", seed_info.ed25519_pub_key);
        }
    }
    Ok(())
}
