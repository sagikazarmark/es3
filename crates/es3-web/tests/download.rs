use es3_web::download::{DownloadOutcome, download_bytes};

#[test]
fn download_bytes_without_runtime_reports_runtime_requirement() {
    let result: Result<DownloadOutcome, String> = download_bytes("a.txt", b"a");

    assert_eq!(result.unwrap_err(), "downloads require the wasm web build");
}
