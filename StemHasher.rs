use pyo3::prelude::*;
use blake3::{Hasher, OUT_LEN};

fn calculate_stem_hash(timestamp: u64, data: &str, fruits: Vec<&str>, previous_hash: &str, nonce: u64) -> String {
  let mut hasher = Hasher::new();
  hasher.update(timestamp.to_le_bytes().into());
  hasher.update(data.as_bytes());
  for fruit in fruit_data {
      hasher.update(fruit.as_bytes());
  }
  hasher.update(previous_hash.as_bytes());
  hasher.update(&nonce.to_le_bytes());
  let mut output = [0u8; OUT_LEN];
  hasher.finalize(&mut output);
  hex::encode(output)
}

/// The module's initialization function
#[pymodule]
fn rusty(_py: Python, m: &PyModule) -> PyResult<()> {
  m.add_function(wrap_pyfunction!(calculate_stem_hash, m)?)?;
  Ok(())
}

   fn _mine_for_nonce_range(data: Vec<u8>, previous_hash: String, difficulty: u32) -> Option<String> {
    let mut hasher = Hasher::new();
    hasher.update(&data);
    hasher.update(previous_hash.as_bytes());
  
    for nonce in 0..std::u32::MAX {
        hasher.update(&nonce.to_le_bytes());
        let result = format!("{:x}", hasher.finalize());
  
        if &result[..difficulty as usize] == "0" * difficulty as usize {
            return Some(result);
        } else {
            // Reset the hasher for the next iteration
            hasher.reset();
            hasher.update(&data);
            hasher.update(previous_hash.as_bytes());
        }
    }
  
    None
  }