use std::{env, io};
use winresource::WindowsResource;

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");  // Force rebuild on script changes

    if env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let mut res = WindowsResource::new();
        res.set_icon("assets/icon.ico")
            .set("FileVersion", env!("CARGO_PKG_VERSION"))  // Force version change
            .set("ProductVersion", env!("CARGO_PKG_VERSION"));

        res.compile()?;
    }
    Ok(())
}