use crate::*;

/// If cargo exists on the system, try to build lair manually.
pub fn cargo_build_lair_executable() -> LairResult<()> {
    match std::process::Command::new("cargo")
        .args(&[
            "install",
            "lair_keystore",
            "-f",
            "--version",
            crate::LAIR_VER,
            "--bin",
            "lair-keystore",
        ])
        .spawn()
        .map_err(LairError::other)?
        .wait()
    {
        Ok(_) => Ok(()),
        Err(e) => Err(LairError::other(e)),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "cargo-compile-test")]
    fn cargo_compile_test() {
        super::cargo_build_lair_executable().unwrap();
    }
}
