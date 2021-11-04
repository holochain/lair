//! We want both ergonomic structs on the rust side, and compact encoding
//! on the encoded binary side. The hcSeedBundle encoding spec uses msgpack
//! arrays to compact the encoding. These structs translate between that
//! compact encoding and the more ergonomic rust data structures.

use super::*;

/// The more ergonomic rust structure of an (encrypted) seed bundle.
#[derive(Debug)]
pub(crate) struct SeedBundle {
    /// The list of ciphers that will allow decrypting the seed.
    pub cipher_list: Box<[SeedCipher]>,

    /// The encoded app_data associated with this bundle.
    pub app_data: Box<[u8]>,
}

/// A helper struct to serialize a seed bundle in the compact msgpack array fmt.
#[derive(serde::Serialize)]
struct ISer<'lt>(
    &'lt str,
    &'lt [SeedCipher],
    #[serde(with = "serde_bytes")] &'lt [u8],
);

impl serde::Serialize for SeedBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ISer("hcsb0", &self.cipher_list, &self.app_data).serialize(serializer)
    }
}

/// A helper struct for deserializing a seed bundle from the compact msgpack fmt
#[derive(serde::Deserialize)]
struct IDes<'lt>(
    &'lt str,
    Box<[SeedCipher]>,
    #[serde(with = "serde_bytes")] Box<[u8]>,
);

impl<'de> serde::Deserialize<'de> for SeedBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let dec: IDes<'de> = serde::Deserialize::deserialize(deserializer)?;
        if dec.0 != "hcsb0" {
            return Err(serde::de::Error::custom(format!(
                "unsupported bundle version: {}",
                dec.0
            )));
        }
        Ok(SeedBundle {
            cipher_list: dec.1,
            app_data: dec.2,
        })
    }
}

/// The more ergonomic rust structure of an (encrypted) seed cipher.
#[derive(Debug)]
pub(crate) enum SeedCipher {
    /// PwHash type seed cipher
    PwHash {
        /// argon salt
        salt: U8Array<16>,

        /// argon mem limit
        mem_limit: u32,

        /// argon ops limit
        ops_limit: u32,

        /// secretstream header
        header: U8Array<24>,

        /// secretstream cipher
        cipher: U8Array<49>,
    },
    /// Security Questions type seed cipher
    SecurityQuestions {
        /// argon salt
        salt: U8Array<16>,

        /// argon mem limit
        mem_limit: u32,

        /// argon ops limit
        ops_limit: u32,

        /// the three security questions to ask the user
        question_list: (String, String, String),

        /// secretstream header
        header: U8Array<24>,

        /// secretstream cipher
        cipher: U8Array<49>,
    },
}

impl serde::Serialize for SeedCipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // serialize into the more compact msgpack array format
        match self {
            Self::PwHash {
                salt,
                mem_limit,
                ops_limit,
                header,
                cipher,
            } => ("pw", salt, mem_limit, ops_limit, header, cipher)
                .serialize(serializer),
            Self::SecurityQuestions {
                salt,
                mem_limit,
                ops_limit,
                question_list,
                header,
                cipher,
            } => (
                "qa",
                salt,
                mem_limit,
                ops_limit,
                &question_list.0,
                &question_list.1,
                &question_list.2,
                header,
                cipher,
            )
                .serialize(serializer),
        }
    }
}

impl<'de> serde::Deserialize<'de> for SeedCipher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // deserializing the compact msgpack array format is a little more
        // complicated. We need to implement a visitor that can change
        // behavior after reading the first "type" marker at the beginning
        // of the array

        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = SeedCipher;

            fn expecting(
                &self,
                f: &mut std::fmt::Formatter<'_>,
            ) -> std::fmt::Result {
                write!(f, "SeedCipher array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                // DRY out the following by macroizing the redundant
                // next_element boilerplate.
                macro_rules! next_elem {
                    ($t:ty, $s:ident, $e:literal) => {{
                        let out: $t = match $s.next_element() {
                            Ok(Some(t)) => t,
                            _ => return Err(serde::de::Error::custom($e)),
                        };
                        out
                    }};
                }

                // read the first element of the array, the "type" marker
                let type_name =
                    next_elem!(&'de str, seq, "expected cipher type_name");

                // switch based on that type marker
                match type_name {
                    "pw" => {
                        let salt =
                            next_elem!(U8Array<16>, seq, "expected salt");
                        let mem_limit =
                            next_elem!(u32, seq, "expected mem_limit");
                        let ops_limit =
                            next_elem!(u32, seq, "expected ops_limit");
                        let header =
                            next_elem!(U8Array<24>, seq, "expected header");
                        let cipher =
                            next_elem!(U8Array<49>, seq, "expected cipher");
                        Ok(SeedCipher::PwHash {
                            salt,
                            mem_limit,
                            ops_limit,
                            header,
                            cipher,
                        })
                    }
                    "qa" => {
                        let salt =
                            next_elem!(U8Array<16>, seq, "expected salt");
                        let mem_limit =
                            next_elem!(u32, seq, "expected mem_limit");
                        let ops_limit =
                            next_elem!(u32, seq, "expected ops_limit");
                        let q1 = next_elem!(String, seq, "expected question 1");
                        let q2 = next_elem!(String, seq, "expected question 2");
                        let q3 = next_elem!(String, seq, "expected question 3");
                        let header =
                            next_elem!(U8Array<24>, seq, "expected header");
                        let cipher =
                            next_elem!(U8Array<49>, seq, "expected cipher");
                        Ok(SeedCipher::SecurityQuestions {
                            salt,
                            mem_limit,
                            ops_limit,
                            question_list: (q1, q2, q3),
                            header,
                            cipher,
                        })
                    }
                    oth => {
                        return Err(serde::de::Error::custom(format!(
                            "unsupported cipher type: {}",
                            oth
                        )))
                    }
                }
            }
        }

        deserializer.deserialize_seq(V)
    }
}
