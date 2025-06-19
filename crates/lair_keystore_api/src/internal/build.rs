use std::path::PathBuf;

const WORKSPACE_CARGO_TOML_PATH: &str = "../../Cargo.toml";
const CARGO_TOML_PATH: &str = "./Cargo.toml";
const VER_FILE_PATH: &str = "./ver.rs";
const BUILD_RS_PATH: &str = "./build.rs";

/// Generate the ver.rs file in OUT_DIR containing LAIR_VER constant.
pub fn build_ver() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let ver_file = std::path::Path::new(&out_dir).join(VER_FILE_PATH);
    println!("cargo:rerun-if-changed={BUILD_RS_PATH}");
    println!("cargo:rerun-if-changed={WORKSPACE_CARGO_TOML_PATH}");

    let parent_toml_version = PathBuf::from(WORKSPACE_CARGO_TOML_PATH);
    let ver = if parent_toml_version.exists() {
        // When doing a build or release build, we have to read the version from the workspace Cargo.toml.
        let cargo_toml: toml::Value = toml::from_str(
            &std::fs::read_to_string(&parent_toml_version)
                .expect("Failed to read workspace Cargo.toml"),
        )
        .unwrap();
        cargo_toml
            .as_table()
            .unwrap()
            .get("workspace")
            .unwrap()
            .as_table()
            .unwrap()
            .get("package")
            .unwrap()
            .as_table()
            .unwrap()
            .get("version")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    } else {
        // When publishing, the manifest gets rewritten to contain the version to publish with and
        // the workspace Cargo.toml is not available.
        let cargo_toml: toml::Value = toml::from_str(
            &std::fs::read_to_string(CARGO_TOML_PATH)
                .expect("Failed to read project Cargo.toml"),
        )
        .unwrap();
        cargo_toml
            .as_table()
            .unwrap()
            .get("package")
            .unwrap()
            .as_table()
            .unwrap()
            .get("version")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    };

    std::fs::write(
        ver_file,
        format!("/// Lair Version\npub const LAIR_VER: &str = \"{ver}\";\n",),
    )
    .unwrap();
}
