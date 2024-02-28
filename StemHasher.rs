// StemHasher.rs

use pyo3::prelude::*;
use blake3::{Hasher, OUT_LEN};
use std::convert::TryInto;

#[pyfunction]
fn calculate_stem_hash(py: Python, timestamp: u64, data: &str, fruits: Vec<&str>, previous_hash: &str, starting_nonce: u64, difficulty: u32) -> PyResult<(String, u64)> {
    let mut nonce = starting_nonce;
    loop {
        let mut hasher = Hasher::new();
        hasher.update(timestamp.to_le_bytes().into());
        hasher.update(data.as_bytes());
        for fruit in &fruits {
            hasher.update(fruit.as_bytes());
        }
        hasher.update(previous_hash.as_bytes());
        hasher.update(&nonce.to_le_bytes());
        let mut output = [0u8; OUT_LEN];
        hasher.finalize(&mut output);
        let hash = hex::encode(output);

        if &hash[..difficulty as usize] == "0".repeat(difficulty as usize) {
            return Ok((hash, nonce));
        }

        // Increment nonce for the next iteration
        nonce += 1;
    }
}

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

  
    None
  }
