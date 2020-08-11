//! Ed25519 Signature Utilities
//! NOTE - temporarily using RING crate until we switch to sodoken

use crate::*;

/// Result data for sign_ed25519_keypair_new_from_entropy.
#[derive(Debug)]
pub struct SignEd25519KeypairResult {
    /// Private key bytes.
    /// @todo - once we're integrated with sodoken, make this a priv buffer.
    pub priv_key: Arc<Vec<u8>>,

    /// Public key bytes.
    pub pub_key: Arc<Vec<u8>>,
}

/// Generate a new random ed25519 signature keypair.
pub async fn sign_ed25519_keypair_new_from_entropy(
) -> LairResult<SignEd25519KeypairResult> {
    rayon_exec(move || {
        let sys_rand = ring::rand::SystemRandom::new();
        let mut priv_key = vec![0; 32];
        ring::rand::SecureRandom::fill(&sys_rand, &mut priv_key)
            .map_err(|e| format!("{:?}", e))?;
        let keypair =
            ring::signature::Ed25519KeyPair::from_seed_unchecked(&priv_key)
                .map_err(|e| format!("{:?}", e))?;
        let pub_key = ring::signature::KeyPair::public_key(&keypair)
            .as_ref()
            .to_vec();
        Ok(SignEd25519KeypairResult {
            priv_key: Arc::new(priv_key),
            pub_key: Arc::new(pub_key),
        })
    })
    .await
}

/// Generate detached signature bytes for given ed25519 priv key / message.
pub async fn sign_ed25519(
    priv_key: Arc<Vec<u8>>,
    message: Arc<Vec<u8>>,
) -> LairResult<Arc<Vec<u8>>> {
    rayon_exec(move || {
        let keypair =
            ring::signature::Ed25519KeyPair::from_seed_unchecked(&priv_key)
                .map_err(|e| format!("{:?}", e))?;
        let signature = keypair.sign(&message);
        Ok(Arc::new(signature.as_ref().to_vec()))
    })
    .await
}

/// Verify signature on given message with given public key.
pub async fn sign_ed25519_verify(
    pub_key: Arc<Vec<u8>>,
    message: Arc<Vec<u8>>,
    signature: Arc<Vec<u8>>,
) -> LairResult<bool> {
    rayon_exec(move || {
        let pub_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            &*pub_key,
        );
        Ok(pub_key.verify(&message, &signature).is_ok())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(threaded_scheduler)]
    async fn it_can_sign_and_verify() {
        let msg = Arc::new(vec![0, 1, 2, 3]);

        let SignEd25519KeypairResult { priv_key, pub_key } =
            sign_ed25519_keypair_new_from_entropy().await.unwrap();

        let sig = sign_ed25519(priv_key.clone(), msg.clone()).await.unwrap();

        assert!(
            sign_ed25519_verify(pub_key.clone(), msg.clone(), sig.clone(),)
                .await
                .unwrap()
        );

        let mut bad_sig = (*sig).clone();
        use std::num::Wrapping;
        bad_sig[0] = (Wrapping(bad_sig[0]) + Wrapping(1)).0;
        assert!(!sign_ed25519_verify(
            pub_key.clone(),
            msg.clone(),
            Arc::new(bad_sig),
        )
        .await
        .unwrap());
    }
}
