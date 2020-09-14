//! Utilities for generating / managing TLS certificates and keypairs.

use crate::*;
use actor::{TlsCertAlg, TlsCertOptions};

/// Generate a new random Tls keypair and self signed certificate.
pub async fn tls_cert_self_signed_new_from_entropy(
    options: TlsCertOptions,
) -> LairResult<entry::EntryTlsCert> {
    rayon_exec(move || {
        let sni = format!("a{}a.a{}a", nanoid::nanoid!(), nanoid::nanoid!());
        let mut params = rcgen::CertificateParams::new(vec![sni.clone()]);
        #[allow(unreachable_patterns)]
        match options.alg {
            TlsCertAlg::PkcsEd25519 => params.alg = &rcgen::PKCS_ED25519,
            TlsCertAlg::PkcsEcdsaP256Sha256 => {
                params.alg = &rcgen::PKCS_ECDSA_P256_SHA256
            }
            TlsCertAlg::PkcsEcdsaP384Sha384 => {
                params.alg = &rcgen::PKCS_ECDSA_P384_SHA384
            }
            TlsCertAlg::PkcsEd25519 => params.alg = &rcgen::PKCS_ED25519,
            _ => {
                return Err(
                    format!("unhandled cert alg: {:?}", options.alg).into()
                )
            }
        };
        let cert = rcgen::Certificate::from_params(params)
            .map_err(LairError::other)?;
        let priv_key_der = cert.serialize_private_key_der();
        let cert_der = cert.serialize_der().map_err(LairError::other)?;
        let cert_digest = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state()
            .update(&cert_der)
            .finalize()
            .as_bytes()
            .to_vec();
        Ok(entry::EntryTlsCert {
            sni: sni.into(),
            priv_key_der: priv_key_der.into(),
            cert_der: cert_der.into(),
            cert_digest: cert_digest.into(),
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(threaded_scheduler)]
    async fn it_can_tls_cert_gen() {
        let cert_res =
            tls_cert_self_signed_new_from_entropy(TlsCertOptions::default())
                .await
                .unwrap();
        println!("cert: {:?}", cert_res);
        // we can't assert any values here as they are all random
        // when we have more functionality an integration test can be written
        // that takes the generated cert and makes sure it is usable
        // to encrypt / decrypt
    }
}
