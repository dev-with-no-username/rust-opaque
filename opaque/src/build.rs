extern crate cbindgen;

fn main() {
    // let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let gen = cbindgen::Builder::new();
    gen.with_language(cbindgen::Language::C)
        .with_crate("./")
        .generate()
        .expect("Unable to generate binding headers")
        .write_to_file("./examples/librust.h");
}
