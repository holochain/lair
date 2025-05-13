use lair_keystore_api::dependencies::*;
use lair_keystore_api::in_proc_keystore::*;
use lair_keystore_api::mem_store::*;
use lair_keystore_api::prelude::*;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() {
    let (_keystore1, client1) = new_keystore().await;

    println!("# Generating random root seed for client1");

    // ensure root seed exists
    let root_pk = client1
        .new_seed("root".into(), None, true)
        .await
        .unwrap()
        .x25519_pub_key;

    // extract the mnemonic
    let to_save = extract_root_mnemonic(&client1, root_pk).await;

    println!("# SAVE THIS: {to_save}");

    println!("# Deriving keys from client1");

    let client1_keys = derive_keys(&client1).await;

    println!("# IMPORTING SAVED MNEMONIC into client2");

    let (_keystore2, client2) = new_keystore().await;

    import_root_mnemonic(&client2, to_save).await;

    println!("# Deriving keys from client2");

    let client2_keys = derive_keys(&client2).await;

    assert_eq!(client1_keys, client2_keys);

    println!("# They are equal!");
}

async fn new_keystore() -> (InProcKeystore, LairClient) {
    let passphrase = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"passphrase".to_vec(),
    )));

    let config = hc_seed_bundle::PwHashLimits::Minimum
        .with_exec(|| LairServerConfigInner::new("/", passphrase.clone()))
        .await
        .unwrap();

    let keystore = InProcKeystore::new(
        Arc::new(config),
        create_mem_store_factory(),
        passphrase.clone(),
    )
    .await
    .unwrap();

    let client = keystore.new_client().await.unwrap();

    (keystore, client)
}

async fn extract_root_mnemonic(
    client: &LairClient,
    root_pk: X25519PubKey,
) -> String {
    // first set up a temp keypair for accepting the export
    let mut tmp_pk = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
    let mut tmp_sk = sodoken::SizedLockedArray::new().unwrap();
    sodoken::crypto_box::xsalsa_keypair(&mut tmp_pk, &mut tmp_sk.lock())
        .unwrap();

    // export encrypts the seed for the temp key
    let (nonce, enc) = client
        .export_seed_by_tag("root".into(), root_pk.clone(), tmp_pk.into(), None)
        .await
        .unwrap();

    let mut key = [0; 32];

    // decrypt using our temp key
    sodoken::crypto_box::xsalsa_open_easy(
        &mut key,
        &enc,
        &nonce,
        &root_pk,
        &tmp_sk.lock(),
    )
    .unwrap();

    // now convert it into an english mnemonic
    mnemonic::to_string(&key[..])
}

async fn import_root_mnemonic(client: &LairClient, to_save: String) {
    // first, decode the mnemonic
    let mut key = [0; 32];
    mnemonic::decode(to_save, &mut key[..]).unwrap();

    // generate an import key for lair to receive the import
    let import_pk = client
        .new_seed("import".into(), None, true)
        .await
        .unwrap()
        .x25519_pub_key;

    // we need a temp keypair again to do the import encryption
    let mut tmp_pk = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
    let mut tmp_sk = sodoken::SizedLockedArray::new().unwrap();
    sodoken::crypto_box::xsalsa_keypair(&mut tmp_pk, &mut tmp_sk.lock())
        .unwrap();

    // encrypt the seed for import into lair
    let mut nonce = [0; sodoken::crypto_box::XSALSA_NONCEBYTES];
    sodoken::random::randombytes_buf(&mut nonce).unwrap();
    let mut cipher = vec![0; 32 + sodoken::crypto_box::XSALSA_MACBYTES];
    sodoken::crypto_box::xsalsa_easy(
        &mut cipher,
        &key,
        &nonce,
        &import_pk,
        &tmp_sk.lock(),
    )
    .unwrap();

    // do the actual import
    client
        .import_seed(
            tmp_pk.into(),
            import_pk,
            None,
            nonce,
            cipher.into(),
            "root".into(),
            true,
        )
        .await
        .unwrap();
}

async fn derive_key(client: &LairClient, path: Box<[u32]>) -> String {
    use base64::prelude::*;

    // we are just using the debug repr of the path for the result tag name
    BASE64_STANDARD.encode(
        &*client
            .derive_seed(
                "root".into(),
                None,
                format!("sub-key-{path:?}").into(),
                None,
                path,
            )
            .await
            .unwrap()
            .ed25519_pub_key,
    )
}

async fn derive_keys(client: &LairClient) -> Vec<String> {
    const REVOKE: u32 = 1;
    const DEVICE: u32 = 2;

    let revoke = derive_key(client, vec![REVOKE].into()).await;
    println!("- revoke: {revoke}");

    let device1app1 = derive_key(client, vec![DEVICE, 1, 1].into()).await;
    println!("- device1app1: {device1app1}");

    let device1app2 = derive_key(client, vec![DEVICE, 1, 2].into()).await;
    println!("- device1app2: {device1app2}");

    vec![revoke, device1app1, device1app2]
}
