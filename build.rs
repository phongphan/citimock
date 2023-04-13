use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    show_link_libraries();

    // Tel cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=xmlsec_wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("xmlsec_wrapper.h")
        .clang_args(get_cflags())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindigs to the $OUT_DIR/xmlsec_bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("xmlsec_bindings.rs"))
        .expect("Couldn't write bindings");
}

// Tell cargo:rustc to add the link libraries
fn show_link_libraries() {
    for arg in get_ldflags().iter() {
        if let Some(lib) = arg.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={}", lib);
        } else if let Some(path) = arg.strip_prefix("-L") {
            println!("cargo:rustc-link-search={}", path);
        }
    }
}

fn get_cflags() -> Vec<String> {
    let output = Command::new("xmlsec1-config")
        .arg("--cflags")
        .output()
        .expect("Failed to get cflags from 'xmlsec1-config --cflags'")
        .stdout;

    split(output)
}

fn get_ldflags() -> Vec<String> {
    let output = Command::new("xmlsec1-config")
        .arg("--libs")
        .output()
        .expect("Failed to get ld flags from 'xmlsec1-config --libs'")
        .stdout;

    split(output)
}

fn split(input: Vec<u8>) -> Vec<String> {
    let s = String::from_utf8(input).expect("Invalid UTF-8");
    s.split_whitespace()
        .map(|p| p.to_owned())
        .collect::<Vec<String>>()
}

/* For debugging purpose:
 *     The xmlsec must be configure with
 *        --prefix=$HOME/libxmlsec1 --disable-crypto-dl --disable-app-crypto-dl --enable-debugger --with-openssl=/opt/homebrew/opt/openssl@1.1 --with-gnutls=no
 */
