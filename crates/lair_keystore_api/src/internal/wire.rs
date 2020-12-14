//! Lair Wire Protocol Utilities

use crate::{
    actor::*, internal::codec, internal::crypto_box, internal::sign_ed25519,
    internal::x25519, *,
};
use std::convert::TryInto;

macro_rules! default_encode_setup {
    ($msg_id:ident, $wire_type:ident) => {{
        let mut writer = codec::CodecWriter::new(256)?;
        writer.write_u32(256)?;
        writer.write_u32($wire_type)?;
        writer.write_u64(*$msg_id)?;
        writer
    }};
}

macro_rules! wire_type_meta_macro {
    ($macro_name:ident) => {
        $macro_name! {
            ToCliRequestUnlockPassphrase 0xff000010 true true {
            } |msg_id, wire_type| {
                let writer = default_encode_setup!(msg_id, wire_type);
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                LairWire::ToCliRequestUnlockPassphrase { msg_id }
            },
            ToLairRequestUnlockPassphraseResponse 0xff000011 true false {
                passphrase: String,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_str(passphrase, 128)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let passphrase = reader.read_str()?;
                LairWire::ToLairRequestUnlockPassphraseResponse {
                    msg_id,
                    passphrase,
                }
            },
            ToLairLairGetLastEntryIndex 0x00000010 false true {
            } |msg_id, wire_type| {
                let writer = default_encode_setup!(msg_id, wire_type);
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                LairWire::ToLairLairGetLastEntryIndex { msg_id }
            },
            ToCliLairGetLastEntryIndexResponse 0x00000011 false false {
                last_keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(**last_keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let last_keystore_index = reader.read_u32()?;
                LairWire::ToCliLairGetLastEntryIndexResponse {
                    msg_id,
                    last_keystore_index: last_keystore_index.into(),
                }
            },
            ToLairLairGetEntryType 0x00000020 false true {
                keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(**keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                LairWire::ToLairLairGetEntryType {
                    msg_id,
                    keystore_index: keystore_index.into(),
                }
            },
            ToCliLairGetEntryTypeResponse 0x00000021 false false {
                lair_entry_type: LairEntryType,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(*lair_entry_type as u32)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let lair_entry_type = LairEntryType::parse(reader.read_u32()?)?;
                LairWire::ToCliLairGetEntryTypeResponse {
                    msg_id,
                    lair_entry_type,
                }
            },
            ToLairLairGetServerInfo 0x00000030 false true {
            } |msg_id, wire_type| {
                let writer = default_encode_setup!(msg_id, wire_type);
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                LairWire::ToLairLairGetServerInfo { msg_id }
            },
            ToCliLairGetServerInfoResponse 0x00000031 false false {
                info: LairServerInfo,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_str(&info.name, 64)?;
                writer.write_str(&info.version, 64)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let name = reader.read_str()?;
                let version = reader.read_str()?;
                LairWire::ToCliLairGetServerInfoResponse {
                    msg_id,
                    info: LairServerInfo { name, version },
                }
            },
            ToLairTlsCertNewSelfSignedFromEntropy 0x00000110 false true {
                cert_alg: TlsCertAlg,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(*cert_alg as u32)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_alg = TlsCertAlg::parse(reader.read_u32()?)?;
                LairWire::ToLairTlsCertNewSelfSignedFromEntropy {
                    msg_id,
                    cert_alg,
                }
            },
            ToCliTlsCertNewSelfSignedFromEntropyResponse 0x00000111 false false {
                keystore_index: KeystoreIndex,
                cert_sni: CertSni,
                cert_digest: CertDigest,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(**keystore_index)?;
                writer.write_str(cert_sni, 128)?;
                writer.write_bytes_exact(cert_digest, 32)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                let cert_sni = reader.read_str()?;
                let cert_digest = reader.read_bytes(32)?.to_vec();
                LairWire::ToCliTlsCertNewSelfSignedFromEntropyResponse {
                    msg_id,
                    keystore_index: keystore_index.into(),
                    cert_sni: cert_sni.into(),
                    cert_digest: cert_digest.into(),
                }
            },
            ToLairTlsCertGet 0x00000120 false true {
                keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(**keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                LairWire::ToLairTlsCertGet {
                    msg_id,
                    keystore_index: keystore_index.into(),
                }
            },
            ToCliTlsCertGetResponse 0x00000121 false false {
                cert_sni: CertSni,
                cert_digest: CertDigest,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_str(cert_sni, 128)?;
                writer.write_bytes_exact(cert_digest, 32)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_sni = reader.read_str()?;
                let cert_digest = reader.read_bytes(32)?.to_vec();
                LairWire::ToCliTlsCertGetResponse {
                    msg_id,
                    cert_sni: cert_sni.into(),
                    cert_digest: cert_digest.into(),
                }
            },
            ToLairTlsCertGetCertByIndex 0x00000130 false true {
                keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(**keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                LairWire::ToLairTlsCertGetCertByIndex {
                    msg_id,
                    keystore_index: keystore_index.into(),
                }
            },
            ToCliTlsCertGetCertByIndexResponse 0x00000131 false false {
                cert: Cert,
            } |msg_id, wire_type| {
                let mut writer = codec::CodecWriter::new(1024)?;
                writer.write_u32(1024)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_sized_bytes(cert, 968)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert = reader.read_sized_bytes()?;
                LairWire::ToCliTlsCertGetCertByIndexResponse {
                    msg_id,
                    cert: cert.into(),
                }
            },
            ToLairTlsCertGetCertByDigest 0x00000140 false true {
                cert_digest: CertDigest,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_bytes_exact(cert_digest, 32)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_digest = reader.read_bytes(32)?.to_vec();
                LairWire::ToLairTlsCertGetCertByDigest {
                    msg_id,
                    cert_digest: cert_digest.into(),
                }
            },
            ToCliTlsCertGetCertByDigestResponse 0x00000141 false false {
                cert: Cert,
            } |msg_id, wire_type| {
                let mut writer = codec::CodecWriter::new(1024)?;
                writer.write_u32(1024)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_sized_bytes(cert, 968)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert = reader.read_sized_bytes()?;
                LairWire::ToCliTlsCertGetCertByDigestResponse {
                    msg_id,
                    cert: cert.into(),
                }
            },
            ToLairTlsCertGetCertBySni 0x00000150 false true {
                cert_sni: CertSni,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_str(cert_sni, 128)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_sni = reader.read_str()?;
                LairWire::ToLairTlsCertGetCertBySni {
                    msg_id,
                    cert_sni: cert_sni.into(),
                }
            },
            ToCliTlsCertGetCertBySniResponse 0x00000151 false false {
                cert: Cert,
            } |msg_id, wire_type| {
                let mut writer = codec::CodecWriter::new(1024)?;
                writer.write_u32(1024)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_sized_bytes(cert, 968)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert = reader.read_sized_bytes()?;
                LairWire::ToCliTlsCertGetCertBySniResponse {
                    msg_id,
                    cert: cert.into(),
                }
            },
            ToLairTlsCertGetPrivKeyByIndex 0x00000160 false true {
                keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(**keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                LairWire::ToLairTlsCertGetPrivKeyByIndex {
                    msg_id,
                    keystore_index: keystore_index.into(),
                }
            },
            ToCliTlsCertGetPrivKeyByIndexResponse 0x00000161 false false {
                cert_priv_key: CertPrivKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_sized_bytes(cert_priv_key, 220)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_priv_key = reader.read_sized_bytes()?;
                LairWire::ToCliTlsCertGetPrivKeyByIndexResponse {
                    msg_id,
                    cert_priv_key: cert_priv_key.into(),
                }
            },
            ToLairTlsCertGetPrivKeyByDigest 0x00000170 false true {
                cert_digest: CertDigest,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_bytes_exact(cert_digest, 32)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_digest = reader.read_bytes(32)?.to_vec();
                LairWire::ToLairTlsCertGetPrivKeyByDigest {
                    msg_id,
                    cert_digest: cert_digest.into(),
                }
            },
            ToCliTlsCertGetPrivKeyByDigestResponse 0x00000171 false false {
                cert_priv_key: CertPrivKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_sized_bytes(cert_priv_key, 220)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_priv_key = reader.read_sized_bytes()?;
                LairWire::ToCliTlsCertGetPrivKeyByDigestResponse {
                    msg_id,
                    cert_priv_key: cert_priv_key.into(),
                }
            },
            ToLairTlsCertGetPrivKeyBySni 0x00000180 false true {
                cert_sni: CertSni,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_str(cert_sni, 128)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_sni = reader.read_str()?;
                LairWire::ToLairTlsCertGetPrivKeyBySni {
                    msg_id,
                    cert_sni: cert_sni.into(),
                }
            },
            ToCliTlsCertGetPrivKeyBySniResponse 0x00000181 false false {
                cert_priv_key: CertPrivKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_sized_bytes(cert_priv_key, 220)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_priv_key = reader.read_sized_bytes()?;
                LairWire::ToCliTlsCertGetPrivKeyBySniResponse {
                    msg_id,
                    cert_priv_key: cert_priv_key.into(),
                }
            },
            ToLairSignEd25519NewFromEntropy 0x00000210 false true {
            } |msg_id, wire_type| {
                let writer = default_encode_setup!(msg_id, wire_type);
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                LairWire::ToLairSignEd25519NewFromEntropy { msg_id }
            },
            ToCliSignEd25519NewFromEntropyResponse 0x00000211 false false {
                keystore_index: KeystoreIndex,
                pub_key: sign_ed25519::SignEd25519PubKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(**keystore_index)?;
                writer.write_bytes_exact(pub_key, 32)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                let pub_key = reader.read_bytes(32)?.to_vec();
                LairWire::ToCliSignEd25519NewFromEntropyResponse {
                    msg_id,
                    keystore_index: keystore_index.into(),
                    pub_key: pub_key.into(),
                }
            },
            ToLairSignEd25519Get 0x00000220 false true {
                keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(**keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                LairWire::ToLairSignEd25519Get {
                    msg_id,
                    keystore_index: keystore_index.into(),
                }
            },
            ToCliSignEd25519GetResponse 0x00000221 false false {
                pub_key: sign_ed25519::SignEd25519PubKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_bytes_exact(pub_key, 32)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let pub_key = reader.read_bytes(32)?.to_vec();
                LairWire::ToCliSignEd25519GetResponse {
                    msg_id,
                    pub_key: pub_key.into(),
                }
            },
            ToLairSignEd25519SignByIndex 0x00000230 false true {
                keystore_index: KeystoreIndex,
                message: Arc<Vec<u8>>,
            } |msg_id, wire_type| {
                // outgoing sig requests just need to be the right size...
                let size = 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 4 // keystore index
                    + 8 // message length
                    + message.len(); // message content
                let mut writer = codec::CodecWriter::new_zeroed(size)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(**keystore_index)?;
                writer.write_sized_bytes(message, message.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                let message = Arc::new(reader.read_sized_bytes()?);
                LairWire::ToLairSignEd25519SignByIndex {
                    msg_id,
                    keystore_index: keystore_index.into(),
                    message,
                }
            },
            ToCliSignEd25519SignByIndexResponse 0x00000231 false false {
                signature: sign_ed25519::SignEd25519Signature,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_bytes_exact(signature, 64)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let signature = reader.read_bytes(64)?.to_vec();
                LairWire::ToCliSignEd25519SignByIndexResponse {
                    msg_id,
                    signature: signature.into(),
                }
            },
            ToLairSignEd25519SignByPubKey 0x00000240 false true {
                pub_key: sign_ed25519::SignEd25519PubKey,
                message: Arc<Vec<u8>>,
            } |msg_id, wire_type| {
                // outgoing sig requests just need to be the right size...
                let size = 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 32 // pub_key
                    + 8 // message length
                    + message.len(); // message content
                let mut writer = codec::CodecWriter::new_zeroed(size)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes_exact(pub_key, 32)?;
                writer.write_sized_bytes(message, message.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let pub_key = reader.read_bytes(32)?.to_vec();
                let message = Arc::new(reader.read_sized_bytes()?);
                LairWire::ToLairSignEd25519SignByPubKey {
                    msg_id,
                    pub_key: pub_key.into(),
                    message,
                }
            },
            ToCliSignEd25519SignByPubKeyResponse 0x00000241 false false {
                signature: sign_ed25519::SignEd25519Signature,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_bytes_exact(signature, 64)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let signature = reader.read_bytes(64)?.to_vec();
                LairWire::ToCliSignEd25519SignByPubKeyResponse {
                    msg_id,
                    signature: signature.into(),
                }
            },
            ToLairX25519NewFromEntropy 0x00000242 false true {
            } |msg_id, wire_type| {
                let writer = default_encode_setup!(msg_id, wire_type);
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                LairWire::ToLairX25519NewFromEntropy { msg_id }
            },
            ToCliX25519NewFromEntropyResponse 0x00000243 false false {
                keystore_index: KeystoreIndex,
                pub_key: x25519::X25519PubKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(**keystore_index)?;
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(pub_key), 32)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                let pub_key = reader.read_bytes(32)?.try_into()?;
                LairWire::ToCliX25519NewFromEntropyResponse {
                    msg_id,
                    keystore_index: keystore_index.into(),
                    pub_key,
                }
            },
            ToLairX25519Get 0x00000244 false true {
                keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(**keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                LairWire::ToLairX25519Get {
                    msg_id,
                    keystore_index: keystore_index.into(),
                }
            },
            ToCliX25519GetResponse 0x00000245 false false {
                pub_key: x25519::X25519PubKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(pub_key), 32)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let pub_key = reader.read_bytes(32)?;
                let mut pub_key_array = [0; 32];
                pub_key_array.copy_from_slice(pub_key);
                LairWire::ToCliX25519GetResponse {
                    msg_id,
                    pub_key: pub_key_array.into(),
                }
            },
            ToLairCryptoBoxByIndex 0x00000246 false true {
                keystore_index: KeystoreIndex,
                recipient: x25519::X25519PubKey,
                data: Arc<crypto_box::CryptoBoxData>,
            } |msg_id, wire_type| {
                let size = 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 4 // keystore index
                    + 32 // recipient pub key
                    + 8 // data length
                    + data.len(); // data content
                let mut writer = codec::CodecWriter::new_zeroed(size)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(**keystore_index)?;
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(recipient), 32)?;
                writer.write_sized_bytes(AsRef::<[u8]>::as_ref(&**data), data.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?.into();
                let recipient = reader.read_bytes(32)?.try_into()?;
                let data = Arc::new(reader.read_sized_bytes()?.into());
                LairWire::ToLairCryptoBoxByIndex {
                    msg_id,
                    keystore_index,
                    recipient,
                    data,
                }
            },
            ToCliCryptoBoxByIndexResponse 0x00000247 false false {
                encrypted_data: crypto_box::CryptoBoxEncryptedData,
            } |msg_id, wire_type| {
                let size = 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 24 // nonce length
                    + 8 // encrypted data length
                    + encrypted_data.encrypted_data.len(); // encrypted data
                let mut writer = codec::CodecWriter::new_zeroed(size)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(&encrypted_data.nonce), 24)?;
                writer.write_sized_bytes(AsRef::<[u8]>::as_ref(&**encrypted_data.encrypted_data), encrypted_data.encrypted_data.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let nonce = reader.read_bytes(24)?.try_into()?;
                let encrypted_data = Arc::new(reader.read_sized_bytes()?.into());
                LairWire::ToCliCryptoBoxByIndexResponse {
                    msg_id,
                    encrypted_data: crypto_box::CryptoBoxEncryptedData{
                        nonce,
                        encrypted_data,
                    }
                }
            },
            ToLairCryptoBoxByPubKey 0x00000248 false true {
                pub_key: x25519::X25519PubKey,
                recipient: x25519::X25519PubKey,
                data: Arc<crypto_box::CryptoBoxData>,
            } |msg_id, wire_type| {
                let size = 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 32 // pub key
                    + 32 // recipient
                    + data.len(); // data length
                let mut writer = codec::CodecWriter::new_zeroed(size)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(pub_key), 32)?;
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(recipient), 32)?;
                writer.write_sized_bytes(AsRef::<[u8]>::as_ref(&**data), data.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let pub_key = reader.read_bytes(32)?.try_into()?;
                let recipient = reader.read_bytes(32)?.try_into()?;
                let data = Arc::new(reader.read_sized_bytes()?.into());
                LairWire::ToLairCryptoBoxByPubKey {
                    msg_id,
                    pub_key,
                    recipient,
                    data,
                }
            },
            ToCliCryptoBoxByPubKeyResponse 0x00000249 false false {
                encrypted_data: crypto_box::CryptoBoxEncryptedData,
            } |msg_id, wire_type| {
                let size = 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 24 // nonce length
                    + 8 // encrypted data length
                    + encrypted_data.encrypted_data.len(); // encrypted data
                let mut writer = codec::CodecWriter::new_zeroed(size)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(&encrypted_data.nonce), 24)?;
                writer.write_sized_bytes(AsRef::<[u8]>::as_ref(&**encrypted_data.encrypted_data), encrypted_data.encrypted_data.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let nonce = reader.read_bytes(24)?.try_into()?;
                let encrypted_data = Arc::new(reader.read_sized_bytes()?.into());
                LairWire::ToCliCryptoBoxByPubKeyResponse {
                    msg_id,
                    encrypted_data: crypto_box::CryptoBoxEncryptedData {
                        nonce,
                        encrypted_data,
                    }
                }
            },
            ToLairCryptoBoxOpenByIndex 0x00000250 false true {
                keystore_index: KeystoreIndex,
                sender: x25519::X25519PubKey,
                encrypted_data: Arc<crypto_box::CryptoBoxEncryptedData>,
            } |msg_id, wire_type| {
                let size = 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 4 // keystore index
                    + 32 // sender pub key
                    + 24 // nonce length
                    + 8 // encrypted data length
                    + encrypted_data.encrypted_data.len(); // encrypted data
                let mut writer = codec::CodecWriter::new_zeroed(size)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_u32(**keystore_index)?;
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(sender), 32)?;
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(&encrypted_data.nonce), 24)?;
                writer.write_sized_bytes(AsRef::<[u8]>::as_ref(&**encrypted_data.encrypted_data), encrypted_data.encrypted_data.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?.into();
                let sender = reader.read_bytes(32)?.try_into()?;
                let nonce = reader.read_bytes(24)?.try_into()?;
                let data = Arc::new(reader.read_sized_bytes()?.into());
                LairWire::ToLairCryptoBoxOpenByIndex {
                    msg_id,
                    keystore_index,
                    sender,
                    encrypted_data: Arc::new(crypto_box::CryptoBoxEncryptedData {
                        nonce,
                        encrypted_data: data,
                    }),
                }
            },
            ToCliCryptoBoxOpenByIndexResponse 0x00000251 false false {
                data: crypto_box::CryptoBoxData,
            } |msg_id, wire_type| {
                let size = 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 8 // data length
                    + data.len(); // data
                let mut writer = codec::CodecWriter::new_zeroed(size)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_sized_bytes(AsRef::<[u8]>::as_ref(&**data.data), data.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let data = reader.read_sized_bytes()?.into();
                LairWire::ToCliCryptoBoxOpenByIndexResponse {
                    msg_id,
                    data,
                }
            },
            ToLairCryptoBoxOpenByPubKey 0x00000252 false true {
                pub_key: x25519::X25519PubKey,
                sender: x25519::X25519PubKey,
                encrypted_data: Arc<crypto_box::CryptoBoxEncryptedData>,
            } |msg_id, wire_type| {
                let size = 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 32 // pub key
                    + 32 // sender pub key
                    + 24 // nonce length
                    + 8 // encrypted data length
                    + encrypted_data.encrypted_data.len(); // encrypted data
                let mut writer = codec::CodecWriter::new_zeroed(size)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(pub_key), 32)?;
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(sender), 32)?;
                writer.write_bytes_exact(AsRef::<[u8]>::as_ref(&encrypted_data.nonce), 24)?;
                writer.write_sized_bytes(AsRef::<[u8]>::as_ref(&**encrypted_data.encrypted_data), encrypted_data.encrypted_data.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let pub_key = reader.read_bytes(32)?.try_into()?;
                let sender = reader.read_bytes(32)?.try_into()?;
                let nonce = reader.read_bytes(24)?.try_into()?;
                let encrypted_data = Arc::new(reader.read_sized_bytes()?.into());
                LairWire::ToLairCryptoBoxOpenByPubKey {
                    msg_id,
                    pub_key,
                    sender,
                    encrypted_data: Arc::new(crypto_box::CryptoBoxEncryptedData {
                        nonce,
                        encrypted_data,
                    }),
                }
            },
            ToCliCryptoBoxOpenByPubKeyResponse 0x00000253 false false {
                data: crypto_box::CryptoBoxData,
            } |msg_id, wire_type| {
                let size = 4 // msg len
                    + 4 // msg type
                    + 8 // msg id
                    + 8 // data length
                    + data.len(); // data
                let mut writer = codec::CodecWriter::new_zeroed(size)?;
                writer.write_u32(size as u32)?;
                writer.write_u32(wire_type)?;
                writer.write_u64(*msg_id)?;
                writer.write_sized_bytes(AsRef::<[u8]>::as_ref(&**data.data), data.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let data = reader.read_sized_bytes()?.into();
                LairWire::ToCliCryptoBoxOpenByPubKeyResponse {
                    msg_id,
                    data,
                }
            },
        }
    };
}

macro_rules! lair_wire_type_enum {
    ($(
        $variant:ident $repr:literal $is_evt:literal $is_req:literal {$(
            $p_name:ident: $p_ty:ty,
        )*}
        |$msg_id:ident, $wire_type:ident| $encode:block
        |$reader:ident| $decode:block,
    )*) => {
        #[repr(u32)]
        #[derive(Clone, Copy)]
        #[allow(clippy::enum_variant_names)]
        enum LairWireType {$(
            $variant = $repr,
        )*}

        impl LairWireType {
            /// parse a u32 into a LairWireType
            pub fn parse(d: u32) -> LairResult<Self> {
                Ok(match d {
                    $(
                        x if x == LairWireType::$variant as u32 => {
                            LairWireType::$variant
                        }
                    )*
                    _ => return Err("invalide wire type".into()),
                })
            }
        }
    };
}

wire_type_meta_macro!(lair_wire_type_enum);

macro_rules! lair_wire_enum {
    ($(
        $variant:ident $repr:literal $is_evt:literal $is_req:literal {$(
            $p_name:ident: $p_ty:ty,
        )*} |$msg_id:ident, $wire_type:ident| $encode:block
        |$reader:ident| $decode:block,
    )*) => {
        /// Giant unified lair wire protocol enum.
        #[allow(missing_docs)]
        #[derive(Debug, PartialEq)]
        pub enum LairWire {$(
            $variant {
                msg_id: u64,
                $(
                    $p_name: $p_ty,
                )*
            },
        )*}

        impl LairWire {
            /// Is this an "event" type message?
            pub fn is_event(&self) -> bool {
                match self {$(
                    LairWire::$variant {
                        ..
                    } => {
                        $is_evt
                    }
                )*}
            }

            /// Is this a "request" type message?
            /// If false, this must be a "response" type message.
            pub fn is_req(&self) -> bool {
                match self {$(
                    LairWire::$variant {
                        ..
                    } => {
                        $is_req
                    }
                )*}
            }

            /// Get the msg_id associated with this variant.
            pub fn get_msg_id(&self) -> u64 {
                match self {$(
                    LairWire::$variant {
                        msg_id,
                        ..
                    } => *msg_id,
                )*}
            }

            /// Encode this variant into lair wire protocol binary data.
            #[allow(unused_variables)]
            pub fn encode(&self) -> LairResult<Vec<u8>> {
                match self {$(
                    LairWire::$variant {
                        msg_id: $msg_id,
                        $(
                            $p_name,
                        )*
                    } => {
                        let $wire_type: u32 = $repr;
                        $encode
                    }
                )*}
            }

            /// Returns the amount of data we need to decode the next item.
            pub fn peek_size(data: &[u8]) -> LairResult<usize> {
                if data.len() < 4 {
                    return Err("not enough to read size".into());
                }
                use byteorder::ReadBytesExt;
                let size = match (&data[0..4]).read_u32::<byteorder::LittleEndian>() {
                    Ok(size) => size,
                    Err(e) => return Err(LairError::other(e)),
                };
                Ok(size as usize)
            }

            /// Returns true if we have enough bytes to decode.
            pub fn peek_size_ok(data: &[u8]) -> bool {
                let size = match LairWire::peek_size(data) {
                    Ok(size) => size,
                    Err(_) => return false,
                };
                data.len() >= size as usize
            }

            /// Decode lair wire protocol binary data into enum variant.
            #[allow(unused_mut)]
            #[allow(unused_variables)]
            pub fn decode(data: &[u8]) -> LairResult<Self> {
                if !Self::peek_size_ok(data) {
                    return Err("not enough data to decode".into());
                }
                let mut reader = codec::CodecReader::new(data);
                let _size = reader.read_u32()?;

                let wire_type = LairWireType::parse(reader.read_u32()?)?;

                Ok(match wire_type {
                    $(
                        LairWireType::$variant => {
                            let mut $reader = reader;
                            $decode
                        }
                    )*
                })
            }
        }
    };
}

wire_type_meta_macro!(lair_wire_enum);

trait WriterExt {
    fn write_str(&mut self, s: &str, max: usize) -> LairResult<()>;
    fn write_bytes_exact(&mut self, b: &[u8], len: usize) -> LairResult<()>;
    fn write_sized_bytes(&mut self, b: &[u8], max: usize) -> LairResult<()>;
}

impl WriterExt for codec::CodecWriter {
    fn write_str(&mut self, s: &str, max: usize) -> LairResult<()> {
        let s = s.as_bytes();
        if s.len() > max {
            return Err(format!("exceeded {} byte maximum", max).into());
        }
        self.write_u64(s.len() as u64)?;
        self.write_bytes(s)?;
        Ok(())
    }

    fn write_bytes_exact(&mut self, b: &[u8], len: usize) -> LairResult<()> {
        if b.len() != len {
            return Err(format!(
                "invalid byte count, expected {}, got {}",
                len,
                b.len()
            )
            .into());
        }
        self.write_bytes(b)?;
        Ok(())
    }

    fn write_sized_bytes(&mut self, b: &[u8], max: usize) -> LairResult<()> {
        if b.len() > max {
            return Err(format!("exceeded {} byte maximum", max).into());
        }
        self.write_u64(b.len() as u64)?;
        self.write_bytes(b)?;
        Ok(())
    }
}

trait ReaderExt {
    fn read_str(&mut self) -> LairResult<String>;
    fn read_sized_bytes(&mut self) -> LairResult<Vec<u8>>;
}

impl ReaderExt for codec::CodecReader<'_> {
    fn read_str(&mut self) -> LairResult<String> {
        let len = self.read_u64()?;
        Ok(String::from_utf8_lossy(self.read_bytes(len)?).to_string())
    }

    fn read_sized_bytes(&mut self) -> LairResult<Vec<u8>> {
        let len = self.read_u64()?;
        Ok(self.read_bytes(len)?.to_vec())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) trait TestVal: Sized {
        fn test_val() -> Self;
    }
    macro_rules! test_val {
        ($t:ty, $e:expr) => {
            impl TestVal for $t {
                fn test_val() -> Self {
                    $e
                }
            }
        };
    }
    impl<T: TestVal> TestVal for Arc<T> {
        fn test_val() -> Self {
            Arc::new(TestVal::test_val())
        }
    }
    test_val!(String, "test-val".to_string());
    test_val!(Vec<u8>, vec![0x42; 32]);
    test_val!(LairServerInfo, Default::default());
    test_val!(LairEntryType, Default::default());
    test_val!(TlsCertAlg, Default::default());
    test_val!(KeystoreIndex, 42.into());
    test_val!(Cert, vec![0x42; 32].into());
    test_val!(CertPrivKey, vec![0x42; 32].into());
    test_val!(CertSni, "test-val".to_string().into());
    test_val!(CertDigest, vec![0x42; 32].into());
    test_val!(sign_ed25519::SignEd25519PubKey, vec![0x42; 32].into());
    test_val!(sign_ed25519::SignEd25519Signature, vec![0x42; 64].into());
    test_val!(x25519::X25519PubKey, [0x42; 32].into());
    test_val!(x25519::X25519PrivKey, [0x42; 32].into());
    test_val!(crypto_box::CryptoBoxData, vec![42_u8; 20].into());
    test_val!(
        crypto_box::CryptoBoxEncryptedData,
        crypto_box::CryptoBoxEncryptedData {
            nonce: [42_u8; 24].into(),
            encrypted_data: vec![42_u8; 20].into(),
        }
    );

    macro_rules! lair_wire_enum_test {
        ($(
            $variant:ident $repr:literal $is_evt:literal $is_req:literal {$(
                $p_name:ident: $p_ty:ty,
            )*}
            |$msg_id:ident, $wire_type:ident| $encode:block
            |$reader:ident| $decode:block,
        )*) => {$(
            #[test]
            #[allow(non_snake_case)]
            fn $variant() {
                let item = LairWire::$variant {
                    msg_id: 0,
                    $(
                        $p_name: TestVal::test_val(),
                    )*
                };
                let encoded = item.encode().unwrap();
                let decoded = LairWire::decode(&encoded).unwrap();
                assert_eq!(item, decoded);
            }
        )*};
    }

    wire_type_meta_macro!(lair_wire_enum_test);
}
