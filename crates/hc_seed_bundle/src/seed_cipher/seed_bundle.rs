use super::*;

#[derive(Debug)]
pub(crate) struct SeedBundle {
    pub cipher_list: Box<[SeedCipher]>,
    pub app_data: Box<[u8]>,
}

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

#[derive(Debug)]
pub(crate) enum SeedCipher {
    PwHash {
        salt: U8Array<16>,
        mem_limit: u32,
        ops_limit: u32,
        header: U8Array<24>,
        cipher: U8Array<49>,
    },
    SecurityQuestions {
        salt: U8Array<16>,
        mem_limit: u32,
        ops_limit: u32,
        question_list: (String, String, String),
        header: U8Array<24>,
        cipher: U8Array<49>,
    },
}

impl serde::Serialize for SeedCipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
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
                macro_rules! next_elem {
                    ($t:ty, $s:ident, $e:literal) => {{
                        let out: $t = match $s.next_element() {
                            Ok(Some(t)) => t,
                            _ => return Err(serde::de::Error::custom($e)),
                        };
                        out
                    }};
                }
                let type_name =
                    next_elem!(&'de str, seq, "expected cipher type_name");
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
