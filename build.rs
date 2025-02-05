fn main() {
    // Tell Cargo that if the schema files change, to rerun this build script
    println!("cargo:rerun-if-changed=src/schemas/");
}