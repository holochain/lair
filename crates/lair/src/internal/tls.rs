//! Utilities for generating / managing TLS certificates and keypairs.

use crate::*;

/// Tls keypair algorithm to use.
pub enum TlsCertAlg {
    /// Ed25519 Curve.
    PkcsEd25519,
}

/// Configuration for Tls Certificate Generation.
pub struct TlsCertOptions {
    /// Tls keypair algorithm to use.
    pub alg: TlsCertAlg,
}

impl Default for TlsCertOptions {
    fn default() -> Self {
        Self {
            alg: TlsCertAlg::PkcsEd25519,
        }
    }
}

/// Result of generating a certificate
#[derive(Debug)]
pub struct TlsCertGenerateResult {
    /// The random sni that will be built into the self-signed certificate
    pub sni: String,

    /// Private key bytes.
    /// @todo - once we're integrated with sodoken, make this a priv buffer.
    pub priv_key_der: Vec<u8>,

    /// Certificate bytes.
    pub cert_der: Vec<u8>,

    /// 32 byte blake2b certificate digest.
    pub cert_digest: Vec<u8>,
}

/// Generate a new random Tls keypair and self signed certificate.
pub async fn tls_cert_self_signed_new_from_entropy(
    options: TlsCertOptions,
) -> LairResult<TlsCertGenerateResult> {
    rayon_exec(move || {
        let sni = format!("a{}a.a{}a", nanoid::nanoid!(), nanoid::nanoid!());
        let mut params = rcgen::CertificateParams::new(vec![sni.clone()]);
        match options.alg {
            TlsCertAlg::PkcsEd25519 => params.alg = &rcgen::PKCS_ED25519,
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
        Ok(TlsCertGenerateResult {
            sni,
            priv_key_der,
            cert_der,
            cert_digest,
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
