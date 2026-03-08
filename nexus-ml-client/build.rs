fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("cargo:rerun-if-changed=../proto/inference.proto");
  tonic_build::compile_protos("../proto/inference.proto")?;
  Ok(())
}
