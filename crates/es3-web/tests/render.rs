use dioxus::prelude::*;

#[test]
fn app_renders_privacy_first_shell() {
    let html = dioxus_ssr::render_element(rsx! { es3_web::App {} });

    assert!(html.contains("es3 fájl megnyitása"));
    assert!(html.contains("lang=\"hu-HU\""));
    assert!(html.contains("az Ön eszközén olvassa be"));
    assert!(html.contains("nem hagyja el az Ön eszközét"));
    assert!(html.contains("Válasszon egy ES3 fájlt"));
    assert!(html.contains("Nyelv"));
    assert!(html.contains("Magyar"));
    assert!(html.contains("aria-haspopup=\"listbox\""));
}
