// FIXME: Enable zcash_unstable="nu6". Remove this file when no longer needed.

fn main() {
    println!("cargo:rustc-cfg=zcash_unstable=\"nu6\"");
}
