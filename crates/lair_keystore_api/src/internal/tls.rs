//! Utilities for generating / managing TLS certificates and keypairs.

use crate::*;
use once_cell::sync::Lazy;
use one_err::OneErr;
use std::sync::{Arc, Mutex};

/// The well-known CA keypair in plaintext pem format.
/// Some TLS clients require CA roots to validate client-side certificates.
/// By publishing the private keys here, we are essentially allowing
/// self-signed client certificates.
pub const WK_CA_KEYPAIR_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkxOEyiRyocjLRpQk
RE7/bOwmHtkdLLGQrlz23m4aKQOhRANCAATUDekPM40vfqOMxf00KZwRk6gSciHx
xkzPZovign1qmbu0vZstKoVLXoGvlA/Kral9txqhSEGqIL7TdbKyMMQz
-----END PRIVATE KEY-----"#;

/// The well-known pseudo name/id for the well-known lair CA root.
pub const WK_CA_ID: &str = "aKdjnmYOn1HVc_RwSdxR6qa.aQLW3d5D1nYiSSO2cOrcT7a";

/// This doesn't need to be pub... We need the rcgen::Certificate
/// with the private keys still integrated in order to sign certs.
static WK_CA_RCGEN_CERT: Lazy<Arc<rcgen::Certificate>> = Lazy::new(|| {
    let mut params = rcgen::CertificateParams::new(vec![WK_CA_ID.into()]);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::Any);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "Lair Well-Known Pseudo-Self-Signing CA",
    );
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Holochain Foundation");
    params.key_pair =
        Some(rcgen::KeyPair::from_pem(WK_CA_KEYPAIR_PEM).unwrap());
    let cert = rcgen::Certificate::from_params(params).unwrap();
    Arc::new(cert)
});

/// The well-known lair CA pseudo-self-signing certificate.
pub static WK_CA_CERT_DER: Lazy<Arc<Vec<u8>>> = Lazy::new(|| {
    let cert = WK_CA_RCGEN_CERT.as_ref();
    let cert = cert.serialize_der().unwrap();
    Arc::new(cert)
});

/// Result data for new tls cert generation
pub struct TlsCertGenResult {
    /// sni used in cert
    pub sni: Arc<str>,
    /// certificate private key
    pub priv_key: SharedLockedArray,
    /// the der encoded certificate
    pub cert: Arc<[u8]>,
    /// blake2b digest of der encoded certificate
    pub digest: Arc<[u8; 32]>,
}

/// Generate a new random Tls keypair and self signed certificate.
pub async fn tls_cert_self_signed_new() -> LairResult<TlsCertGenResult> {
    let (sni, priv_key, cert) = tokio::task::spawn_blocking(|| {
        let sni = format!("a{}a.a{}a", nanoid::nanoid!(), nanoid::nanoid!());

        let mut params = rcgen::CertificateParams::new(vec![sni.clone()]);
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;

        /*
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
        */

        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::Any);
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("Lair Pseudo-Self-Signed Cert {}", &sni),
        );

        let cert =
            rcgen::Certificate::from_params(params).map_err(OneErr::new)?;

        let cert_pk = zeroize::Zeroizing::new(cert.serialize_private_key_der());
        let mut priv_key = sodoken::LockedArray::new(cert_pk.len())?;
        priv_key.lock().copy_from_slice(&cert_pk);

        let root_cert = &**WK_CA_RCGEN_CERT;
        let cert_der: Arc<[u8]> = cert
            .serialize_der_with_signer(root_cert)
            .map_err(OneErr::new)?
            .into();

        LairResult::Ok((sni, priv_key, cert_der))
    })
    .await
    .map_err(OneErr::new)??;

    let mut digest = [0; 32];
    sodoken::blake2b::blake2b_hash(&mut digest, &cert, None)?;

    Ok(TlsCertGenResult {
        sni: sni.into(),
        priv_key: Arc::new(Mutex::new(priv_key)),
        cert,
        digest: digest.into(),
    })
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
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
*/
