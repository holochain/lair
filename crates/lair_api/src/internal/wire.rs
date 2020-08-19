//! Lair Wire Protocol Utilities

use crate::{actor::*, internal::codec, *};

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
            ToCliRequestUnlockPassphrase 0xff000010 {
            } |msg_id, wire_type| {
                let writer = default_encode_setup!(msg_id, wire_type);
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                LairWire::ToCliRequestUnlockPassphrase { msg_id }
            },
            ToLairRequestUnlockPassphraseResponse 0xff000011 {
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
            ToLairLairGetLastEntryIndex 0x00000010 {
            } |msg_id, wire_type| {
                let writer = default_encode_setup!(msg_id, wire_type);
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                LairWire::ToLairLairGetLastEntryIndex { msg_id }
            },
            ToCliLairGetLastEntryIndexResponse 0x00000011 {
                last_keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(*last_keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let last_keystore_index = reader.read_u32()?;
                LairWire::ToCliLairGetLastEntryIndexResponse {
                    msg_id,
                    last_keystore_index,
                }
            },
            ToLairLairGetEntryType 0x00000020 {
                keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(*keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                LairWire::ToLairLairGetEntryType {
                    msg_id,
                    keystore_index,
                }
            },
            ToCliLairGetEntryTypeResponse 0x00000021 {
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
            ToLairTlsCertNewSelfSignedFromEntropy 0x00000110 {
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
            ToCliTlsCertNewSelfSignedFromEntropyResponse 0x00000111 {
                keystore_index: KeystoreIndex,
                cert_sni: CertSni,
                cert_digest: CertDigest,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(*keystore_index)?;
                writer.write_str(cert_sni, 128)?;
                writer.write_bytes(cert_digest)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                let cert_sni = Arc::new(reader.read_str()?);
                let cert_digest = Arc::new(reader.read_bytes(32)?.to_vec());
                LairWire::ToCliTlsCertNewSelfSignedFromEntropyResponse {
                    msg_id,
                    keystore_index,
                    cert_sni,
                    cert_digest,
                }
            },
            ToLairTlsCertGet 0x00000120 {
                keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(*keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                LairWire::ToLairTlsCertGet {
                    msg_id,
                    keystore_index,
                }
            },
            ToCliTlsCertGetResponse 0x00000121 {
                cert_sni: CertSni,
                cert_digest: CertDigest,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_str(cert_sni, 128)?;
                writer.write_bytes(cert_digest)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_sni = Arc::new(reader.read_str()?);
                let cert_digest = Arc::new(reader.read_bytes(32)?.to_vec());
                LairWire::ToCliTlsCertGetResponse {
                    msg_id,
                    cert_sni,
                    cert_digest,
                }
            },
            ToLairTlsCertGetCertByIndex 0x00000130 {
                keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(*keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                LairWire::ToLairTlsCertGetCertByIndex {
                    msg_id,
                    keystore_index,
                }
            },
            ToCliTlsCertGetCertByIndexResponse 0x00000131 {
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
                let cert = Arc::new(reader.read_sized_bytes()?);
                LairWire::ToCliTlsCertGetCertByIndexResponse {
                    msg_id,
                    cert,
                }
            },
            ToLairTlsCertGetCertByDigest 0x00000140 {
                cert_digest: CertDigest,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_bytes(cert_digest)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_digest = Arc::new(reader.read_bytes(32)?.to_vec());
                LairWire::ToLairTlsCertGetCertByDigest {
                    msg_id,
                    cert_digest,
                }
            },
            ToCliTlsCertGetCertByDigestResponse 0x00000141 {
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
                let cert = Arc::new(reader.read_sized_bytes()?);
                LairWire::ToCliTlsCertGetCertByDigestResponse {
                    msg_id,
                    cert,
                }
            },
            ToLairTlsCertGetCertBySni 0x00000150 {
                cert_sni: CertSni,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_str(cert_sni, 128)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_sni = Arc::new(reader.read_str()?);
                LairWire::ToLairTlsCertGetCertBySni {
                    msg_id,
                    cert_sni,
                }
            },
            ToCliTlsCertGetCertBySniResponse 0x00000151 {
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
                let cert = Arc::new(reader.read_sized_bytes()?);
                LairWire::ToCliTlsCertGetCertBySniResponse {
                    msg_id,
                    cert,
                }
            },
            ToLairTlsCertGetPrivKeyByIndex 0x00000160 {
                keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(*keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                LairWire::ToLairTlsCertGetPrivKeyByIndex {
                    msg_id,
                    keystore_index,
                }
            },
            ToCliTlsCertGetPrivKeyByIndexResponse 0x00000161 {
                cert_priv_key: CertPrivKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_sized_bytes(cert_priv_key, 220)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_priv_key = Arc::new(reader.read_sized_bytes()?);
                LairWire::ToCliTlsCertGetPrivKeyByIndexResponse {
                    msg_id,
                    cert_priv_key,
                }
            },
            ToLairTlsCertGetPrivKeyByDigest 0x00000170 {
                cert_digest: CertDigest,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_bytes(cert_digest)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_digest = Arc::new(reader.read_bytes(32)?.to_vec());
                LairWire::ToLairTlsCertGetPrivKeyByDigest {
                    msg_id,
                    cert_digest,
                }
            },
            ToCliTlsCertGetPrivKeyByDigestResonse 0x00000171 {
                cert_priv_key: CertPrivKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_sized_bytes(cert_priv_key, 220)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_priv_key = Arc::new(reader.read_sized_bytes()?);
                LairWire::ToCliTlsCertGetPrivKeyByDigestResonse {
                    msg_id,
                    cert_priv_key,
                }
            },
            ToLairTlsCertGetPrivKeyBySni 0x00000180 {
                cert_sni: CertSni,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_str(cert_sni, 128)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_sni = Arc::new(reader.read_str()?);
                LairWire::ToLairTlsCertGetPrivKeyBySni {
                    msg_id,
                    cert_sni,
                }
            },
            ToCliTlsCertGetPrivKeyBySniResponse 0x00000181 {
                cert_priv_key: CertPrivKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_sized_bytes(cert_priv_key, 220)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let cert_priv_key = Arc::new(reader.read_sized_bytes()?);
                LairWire::ToCliTlsCertGetPrivKeyBySniResponse {
                    msg_id,
                    cert_priv_key,
                }
            },
            ToLairSignEd25519NewFromEntropy 0x00000210 {
            } |msg_id, wire_type| {
                let writer = default_encode_setup!(msg_id, wire_type);
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                LairWire::ToLairSignEd25519NewFromEntropy { msg_id }
            },
            ToCliSignEd25519NewFromEntropyResponse 0x00000211 {
                keystore_index: KeystoreIndex,
                pub_key: SignEd25519PubKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(*keystore_index)?;
                writer.write_bytes(pub_key)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                let pub_key = Arc::new(reader.read_bytes(32)?.to_vec());
                LairWire::ToCliSignEd25519NewFromEntropyResponse {
                    msg_id,
                    keystore_index,
                    pub_key,
                }
            },
            ToLairSignEd25519Get 0x00000220 {
                keystore_index: KeystoreIndex,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_u32(*keystore_index)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                LairWire::ToLairSignEd25519Get {
                    msg_id,
                    keystore_index,
                }
            },
            ToCliSignEd25519GetResponse 0x00000221 {
                pub_key: SignEd25519PubKey,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_bytes(pub_key)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let pub_key = Arc::new(reader.read_bytes(32)?.to_vec());
                LairWire::ToCliSignEd25519GetResponse {
                    msg_id,
                    pub_key,
                }
            },
            ToLairSignEd25519SignByIndex 0x00000230 {
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
                writer.write_u32(*keystore_index)?;
                writer.write_sized_bytes(message, message.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let keystore_index = reader.read_u32()?;
                let message = Arc::new(reader.read_sized_bytes()?);
                LairWire::ToLairSignEd25519SignByIndex {
                    msg_id,
                    keystore_index,
                    message,
                }
            },
            ToCliSignEd25519SignByIndexResponse 0x00000231 {
                signature: SignEd25519Signature,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_bytes(signature)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let signature = Arc::new(reader.read_bytes(64)?.to_vec());
                LairWire::ToCliSignEd25519SignByIndexResponse {
                    msg_id,
                    signature,
                }
            },
            ToLairSignEd25519SignByPubKey 0x00000240 {
                pub_key: SignEd25519PubKey,
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
                writer.write_bytes(pub_key)?;
                writer.write_sized_bytes(message, message.len())?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let pub_key = Arc::new(reader.read_bytes(32)?.to_vec());
                let message = Arc::new(reader.read_sized_bytes()?);
                LairWire::ToLairSignEd25519SignByPubKey {
                    msg_id,
                    pub_key,
                    message,
                }
            },
            ToCliSignEd25519SignByPubKeyResponse 0x00000241 {
                signature: SignEd25519Signature,
            } |msg_id, wire_type| {
                let mut writer = default_encode_setup!(msg_id, wire_type);
                writer.write_bytes(signature)?;
                Ok(writer.into_vec())
            } |reader| {
                let msg_id = reader.read_u64()?;
                let signature = Arc::new(reader.read_bytes(32)?.to_vec());
                LairWire::ToCliSignEd25519SignByPubKeyResponse {
                    msg_id,
                    signature,
                }
            },
        }
    };
}

macro_rules! lair_wire_type_enum {
    ($(
        $variant:ident $repr:literal {$(
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
        $variant:ident $repr:literal {$(
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

            /// Returns true if we have enough bytes to decode.
            pub fn peek_size_ok(data: &[u8]) -> bool {
                if data.len() < 4 {
                    return false;
                }
                use byteorder::ReadBytesExt;
                let size = match (&data[0..4]).read_u32::<byteorder::LittleEndian>() {
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
mod tests {
    use super::*;

    macro_rules! lair_wire_enum_test {
        ($(
            $variant:ident $repr:literal {$(
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
                        $p_name: Default::default(),
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
