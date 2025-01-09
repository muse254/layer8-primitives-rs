use layer8_primitives::compression;

#[test]
fn test_compression() {
    // We expect greater compression for a repeating pattern
    {
        let laugh = "Ha".repeat(1000);
        let compressed = compression::compress_data(laugh.as_bytes()).unwrap();

        // the compressed data should be smaller than the original data
        assert!(compressed.len() < laugh.len());
        // calculate the percentage of compression; should be greater than 50%
        assert!((laugh.len() as f64 * 0.5) > compressed.len() as f64);
    }
}
