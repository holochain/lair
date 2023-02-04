const CARGO_TOML_PATH: &str = "./Cargo.toml";
const VER_FILE_PATH: &str = "./ver.rs";
const BUILD_RS_PATH: &str = "./build.rs";

/// Generate the ver.rs file in OUT_DIR containing LAIR_VER constant.
pub fn build_ver() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let ver_file = std::path::Path::new(&out_dir).join(VER_FILE_PATH);
    println!("cargo:rerun-if-changed={BUILD_RS_PATH}");
    println!("cargo:rerun-if-changed={CARGO_TOML_PATH}");

    let cargo_toml: toml::Value =
        toml::from_slice(&std::fs::read(CARGO_TOML_PATH).unwrap()).unwrap();
    let ver = cargo_toml
        .as_table()
        .unwrap()
        .get("package")
        .unwrap()
        .as_table()
        .unwrap()
        .get("version")
        .unwrap()
        .as_str()
        .unwrap();

    std::fs::write(
        ver_file,
        format!(
            "/// Lair Version\npub const LAIR_VER: &str = \"{ver}\";\n",
        ),
    )
    .unwrap();
}
