use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::prelude::*;

pub fn compress_data(chunk: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(chunk).map_err(|e| e.to_string())?;
    Ok(encoder.finish().map_err(|e| e.to_string())?)
}

pub fn decompress_data(compressed_chunk: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = GzDecoder::new(compressed_chunk);
    let mut decompressed_data = Vec::new();
    _ = decoder
        .read_to_end(&mut decompressed_data)
        .map_err(|e| e.to_string())?;

    Ok(decompressed_data)
}
