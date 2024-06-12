use accumulators::{hasher::keccak::KeccakHasher, mmr::MMR, store::memory::InMemoryStore};
use headers_accumulators::hashes::HASHES;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryStore::default();
    let store_rc = Arc::new(store);
    let hasher = Arc::new(KeccakHasher::new());

    let mut mmr = MMR::new(store_rc.clone(), hasher.clone(), None);
    let element_indices = append_to_mmr(&mut mmr, HASHES).await?;

    // Example: Generate a proof for a specific element value
    let element_value = "0x7701fb3ede3096fad1b6546eb3ee18a395263631f21990289807b0364a50d3f4";
    if let Some(index) = element_indices.get(element_value) {
        let proof = mmr.get_proof(*index, None).await?;
        println!("{:?}", proof);

        // Verify the proof
        assert!(
            mmr.verify_proof(proof.clone(), element_value.to_string(), None)
                .await?
        );
    } else {
        println!("Element value not found in MMR");
    }

    Ok(())
}

async fn append_to_mmr(
    mmr: &mut MMR,
    hashes: &[&str],
) -> Result<HashMap<String, usize>, Box<dyn std::error::Error>> {
    let mut element_indices = HashMap::new();

    for &hash in hashes {
        // Append the hashed value to the MMR
        let append_result = mmr.append(hash.to_string()).await?;
        element_indices.insert(hash.to_string(), append_result.element_index);
    }

    Ok(element_indices)
}
