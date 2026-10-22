//! Gzip handling and file reading.

use std::io::Write as _;

use flate2::Compression;
use flate2::write::GzEncoder;
use rpki_ccr::{Ccr, Error};

const DATA: &[u8] = include_bytes!("data/example.ccr");

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[cfg(feature = "gzip")]
#[test]
fn gzip_round_trip() {
    let compressed = gzip(DATA);
    assert!(Ccr::is_gzip(&compressed));
    assert!(!Ccr::is_gzip(DATA));
    assert_eq!(
        Ccr::decode(&compressed).unwrap(),
        Ccr::decode(DATA).unwrap()
    );
    assert!(matches!(Ccr::decode_der(&compressed), Err(Error::Der(_))));
}

#[cfg(feature = "gzip")]
#[test]
fn concatenated_gzip_members() {
    let mut compressed = gzip(&DATA[..700]);
    compressed.extend(gzip(&DATA[700..]));
    assert_eq!(
        Ccr::decode(&compressed).unwrap(),
        Ccr::decode(DATA).unwrap()
    );
}

#[cfg(feature = "gzip")]
#[test]
fn truncated_gzip_is_an_io_error() {
    let compressed = gzip(DATA);
    let truncated = &compressed[..compressed.len() / 2];
    assert!(matches!(Ccr::decode(truncated), Err(Error::Io(_))));
}

#[cfg(not(feature = "gzip"))]
#[test]
fn gzip_without_feature_is_unsupported() {
    assert!(matches!(
        Ccr::decode(&gzip(DATA)),
        Err(Error::GzipUnsupported)
    ));
}

#[test]
fn from_file() {
    let dir = std::env::temp_dir().join(format!("rpki-ccr-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let plain = dir.join("example.ccr");
    std::fs::write(&plain, DATA).unwrap();
    assert_eq!(Ccr::from_file(&plain).unwrap(), Ccr::decode(DATA).unwrap());
    #[cfg(feature = "gzip")]
    {
        let compressed = dir.join("example.ccr.gz");
        std::fs::write(&compressed, gzip(DATA)).unwrap();
        assert_eq!(
            Ccr::from_file(&compressed).unwrap(),
            Ccr::decode(DATA).unwrap()
        );
    }
    assert!(matches!(
        Ccr::from_file(dir.join("missing.ccr")),
        Err(Error::Io(_))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}
