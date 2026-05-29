#[cfg(feature = "web")]
fn main() {
    dioxus::launch(es3_web::App);
}

#[cfg(not(feature = "web"))]
fn main() {}
