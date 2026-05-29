#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, closure::Closure};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadOutcome {
    Requested,
}

#[cfg(target_arch = "wasm32")]
pub fn download_bytes(filename: &str, bytes: &[u8]) -> Result<DownloadOutcome, String> {
    let array = js_sys::Uint8Array::from(bytes);
    let parts = js_sys::Array::new();
    parts.push(&array.buffer());

    let blob = web_sys::Blob::new_with_u8_array_sequence(&parts).map_err(js_error)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob).map_err(js_error)?;

    match click_download_link(filename, &url) {
        Ok(()) => {
            schedule_object_url_revoke(url)?;
            Ok(DownloadOutcome::Requested)
        }
        Err(error) => {
            let _ = web_sys::Url::revoke_object_url(&url);
            Err(error)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn download_bytes(_filename: &str, _bytes: &[u8]) -> Result<DownloadOutcome, String> {
    Err("downloads require the wasm web build".to_owned())
}

#[cfg(target_arch = "wasm32")]
fn click_download_link(filename: &str, url: &str) -> Result<(), String> {
    let window = web_sys::window().ok_or_else(|| "browser window is unavailable".to_owned())?;
    let document = window
        .document()
        .ok_or_else(|| "browser document is unavailable".to_owned())?;
    let body = document
        .body()
        .ok_or_else(|| "document body is unavailable".to_owned())?;

    let anchor = document
        .create_element("a")
        .map_err(js_error)?
        .dyn_into::<web_sys::HtmlAnchorElement>()
        .map_err(|_| "failed to create download link".to_owned())?;

    anchor.set_href(url);
    anchor.set_download(filename);
    anchor
        .style()
        .set_property("display", "none")
        .map_err(js_error)?;

    body.append_child(&anchor).map_err(js_error)?;
    anchor.click();
    anchor.remove();

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn schedule_object_url_revoke(url: String) -> Result<(), String> {
    let window = web_sys::window().ok_or_else(|| "browser window is unavailable".to_owned())?;
    let callback = Closure::once(move || {
        let _ = web_sys::Url::revoke_object_url(&url);
    });

    window
        .set_timeout_with_callback_and_timeout_and_arguments_0(callback.as_ref().unchecked_ref(), 0)
        .map_err(js_error)?;
    callback.forget();

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn js_error(error: wasm_bindgen::JsValue) -> String {
    error
        .as_string()
        .unwrap_or_else(|| "browser API call failed".to_owned())
}
