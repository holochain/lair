//! Utilities for reading/writing lair encodings.

use crate::*;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Seek, SeekFrom, Write};

/// Tls Cert Entry Type Identifier.
pub const TLS_CERT_ENTRY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0x10];

/// Sign Ed25519 Entry Type Identifier.
pub const SIGN_ED25519_ENTRY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0x20];

/// Entry Type Enum
#[derive(Debug, PartialEq, Eq)]
pub enum EntryType {
    /// Tls Cert Entry Type
    TlsCert,

    /// Sign Ed25519 Entry Type
    SignEd25519,
}

/// Read from bytes.
pub struct CodecReader<'lt>(std::io::Cursor<&'lt [u8]>);

impl<'lt> CodecReader<'lt> {
    /// Create a new codec Reader.
    pub fn new(data: &'lt [u8]) -> Self {
        Self(std::io::Cursor::new(data))
    }

    /// Advance cursor beyond a pre-padding element
    pub fn read_pre_padding(&mut self) -> LairResult<()> {
        // pre-padding starts with 4 random bytes
        seek_cur(&mut self.0, 4)?;

        // get the TOTAL pre-padding len
        // then subtract out 8 bytes for header for remaining-len
        let rem_len = read_u32(&mut self.0)? - 8;

        // seek past the remaining len
        seek_cur(&mut self.0, rem_len as i64)?;

        Ok(())
    }

    /// Read an entry type element.
    pub fn read_entry_type(&mut self) -> LairResult<EntryType> {
        match self.read_bytes(8)? {
            TLS_CERT_ENTRY => Ok(EntryType::TlsCert),
            SIGN_ED25519_ENTRY => Ok(EntryType::SignEd25519),
            _ => Err("invalid entry type bytes".into()),
        }
    }

    /// Read a u32 element.
    pub fn read_u32(&mut self) -> LairResult<u32> {
        read_u32(&mut self.0)
    }

    /// Read a u64 element.
    pub fn read_u64(&mut self) -> LairResult<u64> {
        read_u64(&mut self.0)
    }

    /// Read bytes element.
    pub fn read_bytes(&mut self, size: u64) -> LairResult<&[u8]> {
        let start = self.0.position() as usize;
        let end = (self.0.position() + size) as usize;
        let slice = &self.0.get_ref()[start..end];
        seek_cur(&mut self.0, size as i64)?;
        Ok(slice)
    }
}

/// Write to bytes.
pub struct CodecWriter(std::io::Cursor<Vec<u8>>);

impl CodecWriter {
    /// Create a new codec Writer.
    pub fn new(size: usize) -> LairResult<Self> {
        let mut data = vec![0; size];
        let sys_rand = ring::rand::SystemRandom::new();
        ring::rand::SecureRandom::fill(&sys_rand, &mut data)
            .map_err(|e| format!("{:?}", e))?;
        Ok(Self(std::io::Cursor::new(data)))
    }

    /// Convert this codec writer into the underlying Vec<u8>
    pub fn into_vec(self) -> Vec<u8> {
        self.0.into_inner()
    }

    /// Write pre-padding element.
    pub fn write_pre_padding(&mut self, size: u32) -> LairResult<()> {
        if self.0.position() + size as u64 > self.0.get_ref().len() as u64 {
            panic!("pre padding would write beyond end of buffer");
        }

        // pre-padding starts with 4 random bytes
        seek_cur(&mut self.0, 4)?;

        // write the TOTAL length of the pre_padding
        // (should be multiple of 4)
        write_u32(&mut self.0, size)?;

        // seek past the total length (minus rand header + sizeof u32)
        seek_cur(&mut self.0, size as i64 - 8)?;

        Ok(())
    }

    /// Write an entry type element.
    pub fn write_entry_type(
        &mut self,
        entry_type: EntryType,
    ) -> LairResult<()> {
        match entry_type {
            EntryType::TlsCert => self.0.write_all(TLS_CERT_ENTRY),
            EntryType::SignEd25519 => self.0.write_all(SIGN_ED25519_ENTRY),
        }
        .map_err(LairError::other)?;
        Ok(())
    }

    /// Write a u32 element.
    pub fn write_u32(&mut self, val: u32) -> LairResult<()> {
        write_u32(&mut self.0, val)?;
        Ok(())
    }

    /// Write a u64 element.
    pub fn write_u64(&mut self, val: u64) -> LairResult<()> {
        write_u64(&mut self.0, val)?;
        Ok(())
    }

    /// Write bytes element.
    pub fn write_bytes(&mut self, val: &[u8]) -> LairResult<()> {
        self.0.write_all(val).map_err(LairError::other)?;
        Ok(())
    }
}

// -- local helpers -- //

fn seek_cur<T>(cur: &mut std::io::Cursor<T>, amnt: i64) -> LairResult<()>
where
    T: std::convert::AsRef<[u8]>,
{
    cur.seek(SeekFrom::Current(amnt))
        .map_err(LairError::other)?;
    Ok(())
}

fn write_u32<W>(mut writer: W, val: u32) -> LairResult<()>
where
    W: std::io::Write,
{
    writer
        .write_u32::<LittleEndian>(val)
        .map_err(LairError::other)?;
    Ok(())
}

fn read_u32<R>(mut reader: R) -> LairResult<u32>
where
    R: std::io::Read,
{
    reader.read_u32::<LittleEndian>().map_err(LairError::other)
}

fn write_u64<W>(mut writer: W, val: u64) -> LairResult<()>
where
    W: std::io::Write,
{
    writer
        .write_u64::<LittleEndian>(val)
        .map_err(LairError::other)?;
    Ok(())
}

fn read_u64<R>(mut reader: R) -> LairResult<u64>
where
    R: std::io::Read,
{
    reader.read_u64::<LittleEndian>().map_err(LairError::other)
}

// -- tests -- //

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_codec_encode_and_decode() {
        let mut writer = CodecWriter::new(1024).unwrap();
        writer.write_pre_padding(16).unwrap();
        writer.write_pre_padding(16).unwrap();
        writer.write_entry_type(EntryType::TlsCert).unwrap();
        writer.write_entry_type(EntryType::SignEd25519).unwrap();
        writer.write_u64(4).unwrap();
        writer.write_u64(4).unwrap();
        writer.write_bytes(&[42, 42, 42, 42]).unwrap();
        writer.write_bytes(&[43, 43, 43, 43]).unwrap();
        writer.write_pre_padding(16).unwrap();
        writer.write_bytes(&[44, 44, 44, 44]).unwrap();

        let raw = writer.into_vec();

        let mut reader = CodecReader::new(&raw);
        reader.read_pre_padding().unwrap();
        reader.read_pre_padding().unwrap();
        assert_eq!(EntryType::TlsCert, reader.read_entry_type().unwrap());
        assert_eq!(EntryType::SignEd25519, reader.read_entry_type().unwrap());
        assert_eq!(4, reader.read_u64().unwrap());
        assert_eq!(4, reader.read_u64().unwrap());
        assert_eq!(&[42, 42, 42, 42], reader.read_bytes(4).unwrap());
        assert_eq!(&[43, 43, 43, 43], reader.read_bytes(4).unwrap());
        reader.read_pre_padding().unwrap();
        assert_eq!(&[44, 44, 44, 44], reader.read_bytes(4).unwrap());
    }
}
