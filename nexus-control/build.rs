fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("cargo:rerun-if-changed=../proto/control.proto");
  tonic_build::configure()
    .build_server(true)
    .build_client(false)
    .compile(&["../proto/control.proto"], &["../proto"])?;
  Ok(())
}
