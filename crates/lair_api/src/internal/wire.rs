//! Lair Wire Protocol Utilities

use crate::{actor::*, internal::codec, *};

/// Giant unified lair wire protocol enum.
#[allow(missing_docs)]
pub enum LairWire {
    ToCliRequestUnlockPassphrase {
        msg_id: u64,
    },
    ToLairRequestUnlockPassphraseResponse {
        msg_id: u64,
        passphrase: String,
    },
    ToLairLairGetLastEntryIndex {
        msg_id: u64,
    },
    ToCliLairGetLastEntryIndexResponse {
        msg_id: u64,
        last_keystore_index: KeystoreIndex,
    },
    ToLairLairGetEntryType {
        msg_id: u64,
        keystore_index: KeystoreIndex,
    },
    ToCliLairGetEntryTypeResponse {
        msg_id: u64,
        lair_entry_type: LairEntryType,
    },
    ToLairTlsCertNewSelfSignedFromEntropy {
        msg_id: u64,
        cert_alg: TlsCertAlg,
    },
    ToCliTlsCertNewSelfSignedFromEntropyResponse {
        msg_id: u64,
        keystore_index: KeystoreIndex,
        cert_sni: CertSni,
        cert_digest: CertDigest,
    },
    ToLairTlsCertGet {
        msg_id: u64,
        keystore_index: KeystoreIndex,
    },
    ToCliTlsCertGetResponse {
        msg_id: u64,
        cert_sni: CertSni,
        cert_digest: CertDigest,
    },
    ToLairTlsCertGetCertByIndex {
        msg_id: u64,
        keystore_index: KeystoreIndex,
    },
    ToCliTlsCertGetCertByIndexResponse {
        msg_id: u64,
        cert: Cert,
    },
    ToLairTlsCertGetCertByDigest {
        msg_id: u64,
        cert_digest: CertDigest,
    },
    ToCliTlsCertGetCertByDigestResponse {
        msg_id: u64,
        cert: Cert,
    },
    ToLairTlsCertGetCertBySni {
        msg_id: u64,
        cert_sni: CertSni,
    },
    ToCliTlsCertGetCertBySniResponse {
        msg_id: u64,
        cert: Cert,
    },
    ToLairTlsCertGetPrivKeyByIndex {
        msg_id: u64,
        keystore_index: KeystoreIndex,
    },
    ToCliTlsCertGetPrivKeyByIndexResponse {
        msg_id: u64,
        cert_priv_key: CertPrivKey,
    },
    ToLairTlsCertGetPrivKeyByDigest {
        msg_id: u64,
        cert_digest: CertDigest,
    },
    ToCliTlsCertGetPrivKeyByDigestResonse {
        msg_id: u64,
        cert_priv_key: CertPrivKey,
    },
    ToLairTlsCertGetPrivKeyBySni {
        msg_id: u64,
        cert_sni: CertSni,
    },
    ToCliTlsCertGetPrivKeyBySniResponse {
        msg_id: u64,
        cert_priv_key: CertPrivKey,
    },
    ToLairSignEd25519NewFromEntropy {
        msg_id: u64,
    },
    ToCliSignEd25519NewFromEntropyResponse {
        msg_id: u64,
        keystore_index: KeystoreIndex,
        pub_key: SignEd25519PubKey,
    },
    ToLairSignEd25519Get {
        msg_id: u64,
        keystore_index: KeystoreIndex,
    },
    ToCliSignEd25519GetResponse {
        msg_id: u64,
        pub_key: SignEd25519PubKey,
    },
    ToLairSignEd25519SignByIndex {
        msg_id: u64,
        keystore_index: KeystoreIndex,
        message: Arc<Vec<u8>>,
    },
    ToCliSignEd25519SignByIndexResponse {
        msg_id: u64,
        signature: SignEd25519Signature,
    },
    ToLairSignEd25519SignByPubKey {
        msg_id: u64,
        pub_key: SignEd25519PubKey,
        message: Arc<Vec<u8>>,
    },
    ToCliSignEd25519SignByPubKeyResponse {
        msg_id: u64,
        signature: SignEd25519Signature,
    },
}

#[repr(u32)]
#[derive(Clone, Copy)]
#[allow(clippy::enum_variant_names)]
enum LairWireType {
    ToCliRequestUnlockPassphrase = 0xff000010,
    ToLairRequestUnlockPassphraseResponse = 0xff000011,
    ToLairLairGetLastEntryIndex = 0x00000010,
    ToCliLairGetLastEntryIndexResponse = 0x00000011,
    ToLairLairGetEntryType = 0x00000020,
    ToCliLairGetEntryTypeResponse = 0x00000021,
    ToLairTlsCertNewSelfSignedFromEntropy = 0x00000110,
    ToCliTlsCertNewSelfSignedFromEntropyResponse = 0x00000111,
    ToLairTlsCertGet = 0x00000120,
    ToCliTlsCertGetResponse = 0x00000121,
    ToLairTlsCertGetCertByIndex = 0x00000130,
    ToCliTlsCertGetCertByIndexResponse = 0x00000131,
    ToLairTlsCertGetCertByDigest = 0x00000140,
    ToCliTlsCertGetCertByDigestResponse = 0x00000141,
    ToLairTlsCertGetCertBySni = 0x00000150,
    ToCliTlsCertGetCertBySniResponse = 0x00000151,
    ToLairTlsCertGetPrivKeyByIndex = 0x00000160,
    ToCliTlsCertGetPrivKeyByIndexResponse = 0x00000161,
    ToLairTlsCertGetPrivKeyByDigest = 0x00000170,
    ToCliTlsCertGetPrivKeyByDigestResonse = 0x00000171,
    ToLairTlsCertGetPrivKeyBySni = 0x00000180,
    ToCliTlsCertGetPrivKeyBySniResponse = 0x00000181,
    ToLairSignEd25519NewFromEntropy = 0x00000210,
    ToCliSignEd25519NewFromEntropyResponse = 0x00000211,
    ToLairSignEd25519Get = 0x00000220,
    ToCliSignEd25519GetResponse = 0x00000221,
    ToLairSignEd25519SignByIndex = 0x00000230,
    ToCliSignEd25519SignByIndexResponse = 0x00000231,
    ToLairSignEd25519SignByPubKey = 0x00000240,
    ToCliSignEd25519SignByPubKeyResponse = 0x00000241,
}

impl LairWire {
    /// Encode this variant into lair wire protocol binary data.
    pub fn encode(&self) -> LairResult<Vec<u8>> {
        let mut writer = codec::CodecWriter::new(256)?;
        writer.write_pre_padding(16)?;
        writer.write_u32(256)?;

        use LairWire::*;

        match self {
            ToCliRequestUnlockPassphrase { msg_id } => {
                writer.write_u32(
                    LairWireType::ToCliRequestUnlockPassphrase as u32,
                )?;
                writer.write_u64(*msg_id)?;
            }
            ToLairRequestUnlockPassphraseResponse { msg_id, passphrase } => {
                let passphrase = passphrase.as_bytes();
                if passphrase.len() > 128 {
                    return Err("passphrase exceeded 128 byte maximum".into());
                }
                writer.write_u32(
                    LairWireType::ToLairRequestUnlockPassphraseResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u64(passphrase.len() as u64)?;
                writer.write_bytes(passphrase)?;
            }
            ToLairLairGetLastEntryIndex { msg_id } => {
                writer.write_u32(
                    LairWireType::ToLairLairGetLastEntryIndex as u32,
                )?;
                writer.write_u64(*msg_id)?;
            }
            ToCliLairGetLastEntryIndexResponse {
                msg_id,
                last_keystore_index,
            } => {
                writer.write_u32(
                    LairWireType::ToCliLairGetLastEntryIndexResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(*last_keystore_index)?;
            }
            ToLairLairGetEntryType {
                msg_id,
                keystore_index,
            } => {
                writer
                    .write_u32(LairWireType::ToLairLairGetEntryType as u32)?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(*keystore_index)?;
            }
            ToCliLairGetEntryTypeResponse {
                msg_id,
                lair_entry_type,
            } => {
                writer.write_u32(
                    LairWireType::ToCliLairGetEntryTypeResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(*lair_entry_type as u32)?;
            }
            ToLairTlsCertNewSelfSignedFromEntropy { msg_id, cert_alg } => {
                writer.write_u32(
                    LairWireType::ToLairTlsCertNewSelfSignedFromEntropy as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(*cert_alg as u32)?;
            }
            ToCliTlsCertNewSelfSignedFromEntropyResponse {
                msg_id,
                keystore_index,
                cert_sni,
                cert_digest,
            } => {
                let cert_sni = cert_sni.as_bytes();
                if cert_sni.len() > 128 {
                    return Err("cert_sni exceeded 128 byte maximum".into());
                }
                writer.write_u32(
                    LairWireType::ToCliTlsCertNewSelfSignedFromEntropyResponse
                        as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(*keystore_index)?;
                writer.write_bytes(cert_digest)?;
                writer.write_u64(cert_sni.len() as u64)?;
                writer.write_bytes(cert_sni)?;
            }
            ToLairTlsCertGet {
                msg_id,
                keystore_index,
            } => {
                writer.write_u32(LairWireType::ToLairTlsCertGet as u32)?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(*keystore_index)?;
            }
            ToCliTlsCertGetResponse {
                msg_id,
                cert_sni,
                cert_digest,
            } => {
                let cert_sni = cert_sni.as_bytes();
                if cert_sni.len() > 128 {
                    return Err("cert_sni exceeded 128 byte maximum".into());
                }
                writer
                    .write_u32(LairWireType::ToCliTlsCertGetResponse as u32)?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes(cert_digest)?;
                writer.write_u64(cert_sni.len() as u64)?;
                writer.write_bytes(cert_sni)?;
            }
            ToLairTlsCertGetCertByIndex {
                msg_id,
                keystore_index,
            } => {
                writer.write_u32(
                    LairWireType::ToLairTlsCertGetCertByIndex as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(*keystore_index)?;
            }
            ToCliTlsCertGetCertByIndexResponse { msg_id, cert } => {
                if cert.len() > 968 {
                    return Err("cert exceeded 968 byte maximum".into());
                }
                // certs are kinda big
                writer = codec::CodecWriter::new(1024)?;
                writer.write_pre_padding(32)?;
                writer.write_u32(1024)?;
                writer.write_u32(
                    LairWireType::ToCliTlsCertGetCertByIndexResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u64(cert.len() as u64)?;
                writer.write_bytes(cert)?;
            }
            ToLairTlsCertGetCertByDigest {
                msg_id,
                cert_digest,
            } => {
                writer.write_u32(
                    LairWireType::ToLairTlsCertGetCertByDigest as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes(cert_digest)?;
            }
            ToCliTlsCertGetCertByDigestResponse { msg_id, cert } => {
                if cert.len() > 968 {
                    return Err("cert exceeded 968 byte maximum".into());
                }
                // certs are kinda big
                writer = codec::CodecWriter::new(1024)?;
                writer.write_pre_padding(32)?;
                writer.write_u32(1024)?;
                writer.write_u32(
                    LairWireType::ToCliTlsCertGetCertByDigestResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u64(cert.len() as u64)?;
                writer.write_bytes(cert)?;
            }
            ToLairTlsCertGetCertBySni { msg_id, cert_sni } => {
                let cert_sni = cert_sni.as_bytes();
                if cert_sni.len() > 128 {
                    return Err("cert_sni exceeded 128 byte maximum".into());
                }
                writer.write_u32(
                    LairWireType::ToLairTlsCertGetCertBySni as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u64(cert_sni.len() as u64)?;
                writer.write_bytes(cert_sni)?;
            }
            ToCliTlsCertGetCertBySniResponse { msg_id, cert } => {
                if cert.len() > 968 {
                    return Err("cert exceeded 968 byte maximum".into());
                }
                // certs are kinda big
                writer = codec::CodecWriter::new(1024)?;
                writer.write_pre_padding(32)?;
                writer.write_u32(1024)?;
                writer.write_u32(
                    LairWireType::ToCliTlsCertGetCertBySniResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u64(cert.len() as u64)?;
                writer.write_bytes(cert)?;
            }
            ToLairTlsCertGetPrivKeyByIndex {
                msg_id,
                keystore_index,
            } => {
                writer.write_u32(
                    LairWireType::ToLairTlsCertGetPrivKeyByIndex as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(*keystore_index)?;
            }
            ToCliTlsCertGetPrivKeyByIndexResponse {
                msg_id,
                cert_priv_key,
            } => {
                if cert_priv_key.len() > 220 {
                    return Err(
                        "cert priv key exceeded 220 byte maximum".into()
                    );
                }
                writer.write_u32(
                    LairWireType::ToCliTlsCertGetPrivKeyByIndexResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u64(cert_priv_key.len() as u64)?;
                writer.write_bytes(cert_priv_key)?;
            }
            ToLairTlsCertGetPrivKeyByDigest {
                msg_id,
                cert_digest,
            } => {
                writer.write_u32(
                    LairWireType::ToLairTlsCertGetPrivKeyByDigest as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes(cert_digest)?;
            }
            ToCliTlsCertGetPrivKeyByDigestResonse {
                msg_id,
                cert_priv_key,
            } => {
                if cert_priv_key.len() > 220 {
                    return Err(
                        "cert priv key exceeded 220 byte maximum".into()
                    );
                }
                writer.write_u32(
                    LairWireType::ToCliTlsCertGetPrivKeyByDigestResonse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u64(cert_priv_key.len() as u64)?;
                writer.write_bytes(cert_priv_key)?;
            }
            ToLairTlsCertGetPrivKeyBySni { msg_id, cert_sni } => {
                let cert_sni = cert_sni.as_bytes();
                if cert_sni.len() > 128 {
                    return Err("cert_sni exceeded 128 byte maximum".into());
                }
                writer.write_u32(
                    LairWireType::ToLairTlsCertGetPrivKeyBySni as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u64(cert_sni.len() as u64)?;
                writer.write_bytes(cert_sni)?;
            }
            ToCliTlsCertGetPrivKeyBySniResponse {
                msg_id,
                cert_priv_key,
            } => {
                if cert_priv_key.len() > 220 {
                    return Err(
                        "cert priv key exceeded 220 byte maximum".into()
                    );
                }
                writer.write_u32(
                    LairWireType::ToCliTlsCertGetPrivKeyBySniResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u64(cert_priv_key.len() as u64)?;
                writer.write_bytes(cert_priv_key)?;
            }
            ToLairSignEd25519NewFromEntropy { msg_id } => {
                writer.write_u32(
                    LairWireType::ToLairSignEd25519NewFromEntropy as u32,
                )?;
                writer.write_u64(*msg_id)?;
            }
            ToCliSignEd25519NewFromEntropyResponse {
                msg_id,
                keystore_index,
                pub_key,
            } => {
                writer.write_u32(
                    LairWireType::ToCliSignEd25519NewFromEntropyResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(*keystore_index)?;
                writer.write_bytes(pub_key)?;
            }
            ToLairSignEd25519Get {
                msg_id,
                keystore_index,
            } => {
                writer.write_u32(LairWireType::ToLairSignEd25519Get as u32)?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(*keystore_index)?;
            }
            ToCliSignEd25519GetResponse { msg_id, pub_key } => {
                writer.write_u32(
                    LairWireType::ToCliSignEd25519GetResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes(pub_key)?;
            }
            ToLairSignEd25519SignByIndex {
                msg_id,
                keystore_index,
                message,
            } => {
                // outgoing sig requests just need to be the right size...
                let size = 16 // pre padding
                    + 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 4 // keystore index
                    + 8 // message length
                    + message.len(); // message content
                writer = codec::CodecWriter::new(size)?;
                writer.write_pre_padding(16)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(
                    LairWireType::ToLairSignEd25519SignByIndex as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(*keystore_index)?;
                writer.write_u64(message.len() as u64)?;
                writer.write_bytes(message)?;
            }
            ToCliSignEd25519SignByIndexResponse { msg_id, signature } => {
                writer.write_u32(
                    LairWireType::ToCliSignEd25519SignByIndexResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes(signature)?;
            }
            ToLairSignEd25519SignByPubKey {
                msg_id,
                pub_key,
                message,
            } => {
                // outgoing sig requests just need to be the right size...
                let size = 16 // pre padding
                    + 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 32 // pub key
                    + 8 // message length
                    + message.len(); // message content
                writer = codec::CodecWriter::new(size)?;
                writer.write_pre_padding(16)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(
                    LairWireType::ToLairSignEd25519SignByPubKey as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes(pub_key)?;
                writer.write_u64(message.len() as u64)?;
                writer.write_bytes(message)?;
            }
            ToCliSignEd25519SignByPubKeyResponse { msg_id, signature } => {
                writer.write_u32(
                    LairWireType::ToCliSignEd25519SignByPubKeyResponse as u32,
                )?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes(signature)?;
            }
        }

        Ok(writer.into_vec())
    }
}
