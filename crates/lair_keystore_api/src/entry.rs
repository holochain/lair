//! File format entry structs.

use crate::*;

use actor::*;
use internal::codec;
use internal::sign_ed25519::SignEd25519PrivKey;

/// Fixed serialized entry byte count.
pub const ENTRY_SIZE: usize = 1024;

/// Enum of lair entry types for decoding.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum LairEntry {
    /// Tls Cert
    TlsCert(EntryTlsCert),

    /// Sign Ed25519
    SignEd25519(EntrySignEd25519),
}

impl From<EntryTlsCert> for LairEntry {
    fn from(o: EntryTlsCert) -> Self {
        Self::TlsCert(o)
    }
}

impl From<EntrySignEd25519> for LairEntry {
    fn from(o: EntrySignEd25519) -> Self {
        Self::SignEd25519(o)
    }
}

impl LairEntry {
    /// Decode a disk entry.
    /// @todo - once we're integrated with sodoken, this should decrypt too
    ///         otherwise we would first have to load priv keys into unprotected
    ///         memory.
    pub fn decode(data: &[u8]) -> LairResult<LairEntry> {
        let mut reader = codec::CodecReader::new(data);

        reader.read_pre_padding()?;

        let entry_type = reader.read_entry_type()?;

        Ok(match entry_type {
            codec::EntryType::TlsCert => {
                LairEntry::TlsCert(entry_decode_tls_cert(reader)?)
            }
            codec::EntryType::SignEd25519 => {
                LairEntry::SignEd25519(entry_decode_sign_ed25519(reader)?)
            }
        })
    }

    /// Encode this entry for writing to disk.
    /// @todo - once we're integrated with sodoken, this should encrypt too
    ///         otherwise we're writing our priv key to unprotected memory.
    pub fn encode(&self) -> LairResult<Vec<u8>> {
        match self {
            LairEntry::TlsCert(e) => e.encode(),
            LairEntry::SignEd25519(e) => e.encode(),
        }
    }
}

fn entry_decode_tls_cert(
    mut reader: codec::CodecReader<'_>,
) -> LairResult<EntryTlsCert> {
    let sni_len = reader.read_u64()?;
    let sni = String::from_utf8_lossy(reader.read_bytes(sni_len)?).to_string();

    let priv_key_der_len = reader.read_u64()?;
    let priv_key_der = reader.read_bytes(priv_key_der_len)?.to_vec();

    let cert_der_len = reader.read_u64()?;
    let cert_der = reader.read_bytes(cert_der_len)?.to_vec();

    let cert_digest = reader.read_bytes(32)?.to_vec();

    Ok(EntryTlsCert {
        sni: sni.into(),
        priv_key_der: priv_key_der.into(),
        cert_der: cert_der.into(),
        cert_digest: cert_digest.into(),
    })
}

fn entry_decode_sign_ed25519(
    mut reader: codec::CodecReader<'_>,
) -> LairResult<EntrySignEd25519> {
    let priv_key = reader.read_bytes(32)?.to_vec().into();
    let pub_key = reader.read_bytes(32)?.to_vec().into();

    Ok(EntrySignEd25519 { priv_key, pub_key })
}

/// File format entry representing Tls Certificate data.
#[derive(Debug, Clone)]
pub struct EntryTlsCert {
    /// The random sni that will be built into the self-signed certificate
    pub sni: CertSni,

    /// Private key bytes.
    /// @todo - once we're integrated with sodoken, make this a priv buffer.
    pub priv_key_der: CertPrivKey,

    /// Certificate bytes.
    pub cert_der: Cert,

    /// 32 byte blake2b certificate digest.
    pub cert_digest: CertDigest,
}

impl EntryTlsCert {
    /// Encode this entry for writing to disk.
    /// @todo - once we're integrated with sodoken, this should encrypt too
    ///         otherwise we're writing our priv key to unprotected memory.
    pub fn encode(&self) -> LairResult<Vec<u8>> {
        let mut writer = codec::CodecWriter::new(ENTRY_SIZE)?;

        // pre padding
        writer.write_pre_padding(16)?;

        // tls cert entry type
        writer.write_entry_type(codec::EntryType::TlsCert)?;

        // write sni
        let sni_bytes = self.sni.as_bytes();
        writer.write_u64(sni_bytes.len() as u64)?;
        writer.write_bytes(sni_bytes)?;

        // write priv key
        writer.write_u64(self.priv_key_der.len() as u64)?;
        writer.write_bytes(&self.priv_key_der)?;

        // write cert
        writer.write_u64(self.cert_der.len() as u64)?;
        writer.write_bytes(&self.cert_der)?;

        // write digest (always 32 bytes)
        writer.write_bytes(&self.cert_digest[0..32])?;

        Ok(writer.into_vec())
    }
}

/// File format entry representing Sign Ed25519 Keypair data.
#[derive(Debug, Clone)]
pub struct EntrySignEd25519 {
    /// Private key bytes.
    /// @todo - once we're integrated with sodoken, make this a priv buffer.
    pub priv_key: SignEd25519PrivKey,

    /// Public key bytes.
    pub pub_key: SignEd25519PubKey,
}

impl EntrySignEd25519 {
    /// Encode this entry for writing to disk.
    /// @todo - once we're integrated with sodoken, this should encrypt too
    ///         otherwise we're writing our priv key to unprotected memory.
    pub fn encode(&self) -> LairResult<Vec<u8>> {
        let mut writer = codec::CodecWriter::new(ENTRY_SIZE)?;

        // pre padding
        writer.write_pre_padding(64)?;

        // sign ed25519 entry type
        writer.write_entry_type(codec::EntryType::SignEd25519)?;

        // write priv_key (always 32 bytes)
        writer.write_bytes(&self.priv_key[0..32])?;

        // write pub_key (always 32 bytes)
        writer.write_bytes(&self.pub_key[0..32])?;

        Ok(writer.into_vec())
    }

    /// Create a signature for given message with this entry's priv_key.
    pub fn sign(
        &self,
        message: Arc<Vec<u8>>,
    ) -> impl std::future::Future<Output = LairResult<SignEd25519Signature>> + 'static
    {
        let priv_key = self.priv_key.clone();
        internal::sign_ed25519::sign_ed25519(priv_key, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_can_encode_and_decode_sign_ed25519_entry() {
        let e = EntrySignEd25519 {
            priv_key: vec![0xdb; 32].into(),
            pub_key: vec![0x42; 32].into(),
        };
        let d = LairEntry::from(e.clone()).encode().unwrap();
        let e2 = match LairEntry::decode(&d).unwrap() {
            LairEntry::SignEd25519(e2) => e2,
            e2 @ _ => panic!("unexpected type: {:?}", e2),
        };
        assert_eq!(e.priv_key, e2.priv_key);
        assert_eq!(e.pub_key, e2.pub_key);
    }

    #[test]
    fn it_can_encode_and_decode_tls_cert_entry() {
        let e = EntryTlsCert {
            sni: "test".to_string().into(),
            priv_key_der: vec![1, 2].into(),
            cert_der: vec![3, 4].into(),
            cert_digest: vec![0x42; 32].into(),
        };
        let d = LairEntry::from(e.clone()).encode().unwrap();
        let e2 = match LairEntry::decode(&d).unwrap() {
            LairEntry::TlsCert(e2) => e2,
            e2 @ _ => panic!("unexpected type: {:?}", e2),
        };
        assert_eq!(e.sni, e2.sni);
        assert_eq!(e.priv_key_der, e2.priv_key_der);
        assert_eq!(e.cert_der, e2.cert_der);
        assert_eq!(e.cert_digest, e2.cert_digest);
    }
}
