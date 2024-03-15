use pyo3::prelude::*;
use blake3::{Hasher, OUT_LEN};

#[pyfunction]
fn calculate_stem_hash(
    timestamp: u64,
    data: &[u8],
    fruits: Vec<&[u8]>,
    previous_hash: &str,
    starting_nonce: u64,
    difficulty: u32,
    leaf_difficulty_threshold: u32,
) -> PyResult<(String, u64, bool)> {
    let mut nonce = starting_nonce;
    let leading_ones_mask = (1 << difficulty) - 1;
    let leading_ones_target = leading_ones_mask << (256 - difficulty);

    loop {
        let mut hasher = Hasher::new();
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(data);
        for fruit in &fruits {
            hasher.update(fruit);
        }
        hasher.update(previous_hash.as_bytes());
        hasher.update(&nonce.to_le_bytes());

        let mut output = [0u8; OUT_LEN];
        hasher.finalize(&mut output);

        let hash_value = u256::from_be_bytes(output);
        if hash_value >= leading_ones_target {
            let is_leaf = difficulty >= leaf_difficulty_threshold;
            return Ok((hex::encode(output), nonce, is_leaf));
        }

        nonce += 1;
    }
}

#[pymodule]
fn rusty(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(calculate_stem_hash, m)?)?;
    Ok(())
}
