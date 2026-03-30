fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("cargo:rerun-if-changed=../proto/policy.proto");
  tonic_build::configure()
    .build_server(false)
    .build_client(true)
    .compile(&["../proto/policy.proto"], &["../proto"])?;
  Ok(())
}
