use dioxus::prelude::*;
use dioxus_i18n::fluent::FluentArgs;
use dioxus_i18n::prelude::*;
use dioxus_i18n::t;
use dioxus_i18n::unic_langid::{LanguageIdentifier, langid};
use es3::ExtractionUnavailableReason;
use std::rc::Rc;

use crate::download::{self, DownloadOutcome};
use crate::model::DownloadFile;
use crate::session::{self, LoadedDossier};

const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");
const EN_US: LanguageIdentifier = langid!("en-US");
const HU_HU: LanguageIdentifier = langid!("hu-HU");
const EN_US_FTL: &str = include_str!("locales/en-US.ftl");
const HU_HU_FTL: &str = include_str!("locales/hu-HU.ftl");
#[cfg(target_arch = "wasm32")]
const LANGUAGE_STORAGE_KEY: &str = "es3-web-language";

#[derive(Debug, Clone)]
enum AppState {
    Empty,
    Loading(String),
    Loaded(Rc<LoadedDossier>),
    Failed(String),
}

#[allow(non_snake_case)]
pub fn App() -> Element {
    let i18n = use_init_i18n(i18n_config);
    let state = use_signal(|| AppState::Empty);
    let notice = use_signal(|| None::<String>);
    let load_generation = use_signal(|| 0usize);
    let current = state.read().clone();
    let language_tag = i18n.language().to_string();

    rsx! {
        document::Stylesheet { href: TAILWIND_CSS }
        main { "data-theme": "light", lang: "{language_tag}", class: "min-h-screen bg-base-200 text-base-content",
            header { class: "border-b border-base-300 bg-base-100",
                div { class: "mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-10 sm:px-6 lg:flex-row lg:items-start lg:justify-between lg:px-8",
                    div { class: "max-w-3xl",
                        h1 { class: "text-4xl font-bold tracking-tight sm:text-5xl", { t!("app-title") } }
                        p { class: "mt-4 max-w-2xl text-lg leading-8 text-base-content/75",
                            { t!("hero-description") }
                        }
                    }
                    div { class: "flex w-full flex-col items-end gap-4 lg:max-w-md",
                        LanguageSwitcher {}
                        {render_file_handling_callout()}
                    }
                }
            }

            section { class: "mx-auto grid w-full max-w-7xl gap-6 px-4 py-8 sm:px-6 lg:grid-cols-[minmax(20rem,24rem)_minmax(0,1fr)] lg:px-8",
                {render_file_action_card(state, notice, load_generation, i18n)}

                div { class: "min-w-0 space-y-6",
                    if let Some(message) = notice.read().as_ref() {
                        div { class: "alert alert-warning items-start text-sm", role: "status", "aria-live": "polite", "{message}" }
                    }

                    {render_state(current, notice, i18n)}
                }
            }
        }
    }
}

fn i18n_config() -> I18nConfig {
    I18nConfig::new(initial_language())
        .with_fallback(EN_US.clone())
        .with_locale((EN_US.clone(), EN_US_FTL))
        .with_locale((HU_HU.clone(), HU_HU_FTL))
}

fn initial_language() -> LanguageIdentifier {
    stored_language().unwrap_or_else(|| HU_HU.clone())
}

fn stored_language() -> Option<LanguageIdentifier> {
    stored_language_tag().and_then(|tag| supported_language(&tag))
}

fn supported_language(language_tag: &str) -> Option<LanguageIdentifier> {
    match language_tag {
        "en-US" => Some(EN_US.clone()),
        "hu-HU" => Some(HU_HU.clone()),
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
fn stored_language_tag() -> Option<String> {
    browser_storage()?
        .get_item(LANGUAGE_STORAGE_KEY)
        .ok()
        .flatten()
}

#[cfg(not(target_arch = "wasm32"))]
fn stored_language_tag() -> Option<String> {
    None
}

#[cfg(target_arch = "wasm32")]
fn browser_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

fn set_selected_language(i18n: I18n, language: LanguageIdentifier) {
    let mut i18n = i18n;
    i18n.set_language(language.clone());
    persist_language(&language);
}

#[cfg(target_arch = "wasm32")]
fn persist_language(language: &LanguageIdentifier) {
    if let Some(storage) = browser_storage() {
        let _ = storage.set_item(LANGUAGE_STORAGE_KEY, &language.to_string());
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn persist_language(_language: &LanguageIdentifier) {}

#[allow(non_snake_case)]
fn LanguageSwitcher() -> Element {
    let i18n = i18n();
    let mut is_open = use_signal(|| false);
    let current_language = i18n.language();
    let english_selected = current_language == EN_US;
    let hungarian_selected = current_language == HU_HU;
    let dropdown_open = *is_open.read();
    let expanded = dropdown_open.to_string();
    let current_language_name = if english_selected {
        t!("language-english")
    } else {
        t!("language-hungarian")
    };
    let language_label = t!("language-switcher-label");
    let english_title = t!("language-switch-to-english");
    let hungarian_title = t!("language-switch-to-hungarian");
    let english_selected_text = english_selected.to_string();
    let hungarian_selected_text = hungarian_selected.to_string();
    let caret_class = if dropdown_open {
        "size-4 rotate-180 text-base-content/55 transition-transform duration-200 ease-out-quint"
    } else {
        "size-4 text-base-content/55 transition-transform duration-200 ease-out-quint"
    };
    let english_option_class = if english_selected {
        "justify-between rounded-lg bg-primary/10 font-medium text-primary hover:bg-primary/15"
    } else {
        "justify-between rounded-lg text-base-content hover:bg-base-200"
    };
    let hungarian_option_class = if hungarian_selected {
        "justify-between rounded-lg bg-primary/10 font-medium text-primary hover:bg-primary/15"
    } else {
        "justify-between rounded-lg text-base-content hover:bg-base-200"
    };

    rsx! {
        div { class: "dropdown dropdown-end self-end", role: "group", "aria-label": "{language_label}",
            button {
                class: "btn btn-outline btn-sm min-h-11 gap-2 border-base-300 bg-base-100 px-3 font-medium shadow-sm hover:border-primary/45 hover:bg-base-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary",
                r#type: "button",
                "aria-haspopup": "listbox",
                "aria-expanded": "{expanded}",
                "aria-controls": "language-menu",
                onclick: move |_| is_open.set(!dropdown_open),
                span { class: "text-xs font-semibold uppercase tracking-wide text-base-content/55", "{language_label}" }
                span { class: "h-4 w-px bg-base-300", "aria-hidden": "true" }
                span { "{current_language_name}" }
                svg { class: "{caret_class}", "viewBox": "0 0 20 20", fill: "none", "aria-hidden": "true",
                    path { d: "M5 7.5L10 12.5L15 7.5", stroke: "currentColor", "stroke-linecap": "round", "stroke-linejoin": "round", "stroke-width": "1.8" }
                }
            }
            if dropdown_open {
                ul {
                    id: "language-menu",
                    role: "listbox",
                    class: "menu dropdown-content z-20 mt-2 w-56 rounded-box border border-base-300 bg-base-100 p-1.5 shadow-lg",
                    li {
                        button {
                            class: "{hungarian_option_class}",
                            r#type: "button",
                            title: "{hungarian_title}",
                            role: "option",
                            "aria-selected": "{hungarian_selected_text}",
                            onclick: move |_| {
                                set_selected_language(i18n, HU_HU.clone());
                                is_open.set(false);
                            },
                            span { { t!("language-hungarian") } }
                        }
                    }
                    li {
                        button {
                            class: "{english_option_class}",
                            r#type: "button",
                            title: "{english_title}",
                            role: "option",
                            "aria-selected": "{english_selected_text}",
                            onclick: move |_| {
                                set_selected_language(i18n, EN_US.clone());
                                is_open.set(false);
                            },
                            span { { t!("language-english") } }
                        }
                    }
                }
            }
        }
    }
}

fn render_file_handling_callout() -> Element {
    rsx! {
        div { class: "alert alert-warning w-full max-w-md items-start gap-3 border border-warning/45 bg-warning/15 p-4 text-warning-content shadow-sm", role: "note",
            span { class: "flex size-6 shrink-0 items-center justify-center rounded-full bg-warning/35 text-xs font-bold leading-none ring-1 ring-warning/45", "aria-hidden": "true", "!" }
            div { class: "min-w-0",
                p { class: "font-semibold", { t!("privacy-card-title") } }
                p { class: "mt-1 text-sm leading-6 text-warning-content/85", { t!("privacy-card-body") } }
            }
        }
    }
}

fn set_if_current_load(
    mut state: Signal<AppState>,
    load_generation: Signal<usize>,
    generation: usize,
    next_state: AppState,
) {
    if matches!(
        session::load_decision(*load_generation.read(), generation),
        session::LoadDecision::Current
    ) {
        state.set(next_state);
    }
}

fn render_file_action_card(
    state: Signal<AppState>,
    notice: Signal<Option<String>>,
    load_generation: Signal<usize>,
    i18n: I18n,
) -> Element {
    rsx! {
        aside { class: "rounded-box border border-base-300 bg-base-100 p-5 shadow-sm lg:self-start",
            div { class: "space-y-4",
                h2 { class: "text-lg font-semibold tracking-tight", { t!("file-card-title") } }
                {render_file_picker(state, notice, load_generation, i18n)}
            }
        }
    }
}

fn render_file_picker(
    state: Signal<AppState>,
    mut notice: Signal<Option<String>>,
    mut load_generation: Signal<usize>,
    i18n: I18n,
) -> Element {
    rsx! {
        label { class: "flex cursor-pointer flex-col items-center justify-center rounded-box border border-dashed border-primary/35 bg-primary/5 p-6 text-center transition-colors duration-200 ease-out-quint hover:border-primary/60 hover:bg-primary/10 focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-primary",
            span { class: "text-lg font-semibold text-primary", { t!("file-picker-title") } }
            span { class: "mt-2 text-sm text-base-content/65", { t!("file-picker-body") } }
            input {
                class: "file-input file-input-bordered file-input-primary mt-5 min-h-11 w-full max-w-xs bg-base-100",
                r#type: "file",
                accept: ".es3,.et3,application/xml,text/xml",
                onchange: move |evt| {
                    notice.set(None);
                    let generation = load_generation.read().wrapping_add(1);
                    load_generation.set(generation);
                    async move {
                        let Some(file) = evt.files().into_iter().next() else {
                            set_if_current_load(
                                state,
                                load_generation,
                                generation,
                                AppState::Failed(i18n.translate("error-no-file-selected")),
                            );
                            return;
                        };

                        let file_name = file.name();
                        match file.read_string().await {
                            Ok(xml) => load_xml_into_state(
                                state,
                                load_generation,
                                generation,
                                file_name,
                                xml,
                            ),
                            Err(error) => set_if_current_load(
                                state,
                                load_generation,
                                generation,
                                AppState::Failed(translate_string_arg(
                                    i18n,
                                    "error-read-file",
                                    "error",
                                    &error.to_string(),
                                )),
                            ),
                        }
                    }
                }
            }
        }
    }
}

fn load_xml_into_state(
    mut state: Signal<AppState>,
    load_generation: Signal<usize>,
    generation: usize,
    file_name: String,
    xml: String,
) {
    if matches!(
        session::load_decision(*load_generation.read(), generation),
        session::LoadDecision::Stale
    ) {
        return;
    }

    state.set(AppState::Loading(file_name.clone()));
    match session::parse_file(file_name, &xml) {
        Ok(loaded) => set_if_current_load(
            state,
            load_generation,
            generation,
            AppState::Loaded(Rc::new(loaded)),
        ),
        Err(error) => {
            set_if_current_load(state, load_generation, generation, AppState::Failed(error))
        }
    }
}

fn render_state(state: AppState, notice: Signal<Option<String>>, i18n: I18n) -> Element {
    match state {
        AppState::Empty => rsx! {
            section { class: "rounded-box border border-base-300 bg-base-100 p-6 shadow-sm",
                div { class: "max-w-2xl",
                    h2 { class: "text-xl font-semibold tracking-tight", { t!("empty-title") } }
                    p { class: "mt-2 text-base-content/70", { t!("empty-body") } }
                }
                ol { class: "mt-6 grid gap-3 text-sm text-base-content/75 sm:grid-cols-3",
                    li { class: "rounded-box bg-base-200 p-3", span { class: "font-medium text-base-content", { t!("empty-step-choose-title") } } " " { t!("empty-step-choose-body") } }
                    li { class: "rounded-box bg-base-200 p-3", span { class: "font-medium text-base-content", { t!("empty-step-inspect-title") } } " " { t!("empty-step-inspect-body") } }
                    li { class: "rounded-box bg-base-200 p-3", span { class: "font-medium text-base-content", { t!("empty-step-download-title") } } " " { t!("empty-step-download-body") } }
                }
            }
        },
        AppState::Loading(file_name) => rsx! {
            section { class: "rounded-box border border-base-300 bg-base-100 p-6 shadow-sm", role: "status", "aria-live": "polite",
                div { class: "flex items-center gap-3",
                    span { class: "loading loading-spinner loading-md text-primary" }
                    div { class: "min-w-0",
                        h2 { class: "font-semibold", { t!("loading-title") } }
                        p { class: "truncate text-sm text-base-content/70", "{file_name}" }
                    }
                }
                div { class: "mt-6 space-y-3",
                    div { class: "skeleton h-4 w-2/3" }
                    div { class: "skeleton h-4 w-5/6" }
                    div { class: "skeleton h-20 w-full" }
                }
            }
        },
        AppState::Failed(error) => rsx! {
            div { class: "alert alert-error items-start", role: "alert",
                div {
                    h2 { class: "font-semibold", { t!("open-error-title") } }
                    p { class: "text-sm", "{error}" }
                    p { class: "mt-2 text-sm", { t!("open-error-help") } }
                }
            }
        },
        AppState::Loaded(loaded) => render_loaded(loaded, notice, i18n),
    }
}

fn download_all_supported(
    loaded: Rc<LoadedDossier>,
    mut notice: Signal<Option<String>>,
    i18n: I18n,
) {
    spawn(async move {
        match session::extract_all_supported(&loaded) {
            session::DownloadAllDecision::NoSupportedFiles { notice: message } => {
                notice.set(Some(translate_no_supported_notice(i18n, message)));
            }
            session::DownloadAllDecision::RequestDownloads { files, failures } => {
                request_all_downloads(files, notice, failures, i18n);
            }
        }
    });
}

fn request_all_downloads(
    files: Vec<DownloadFile>,
    mut notice: Signal<Option<String>>,
    failures: Vec<String>,
    i18n: I18n,
) {
    notice.set(Some(request_browser_downloads(
        files,
        |file| download::download_bytes(&file.filename, &file.bytes),
        failures,
        i18n,
    )));
}

fn render_loaded(
    loaded: Rc<LoadedDossier>,
    mut notice: Signal<Option<String>>,
    i18n: I18n,
) -> Element {
    let downloadable_count = loaded.rows.iter().filter(|row| row.can_download).count();
    let unsupported_count = loaded.rows.len().saturating_sub(downloadable_count);
    let download_all_title = if downloadable_count == 0 {
        t!("download-all-title-none")
    } else {
        t!("download-all-title-available")
    };
    let rows_for_table = loaded
        .rows
        .iter()
        .cloned()
        .map(|row| {
            let reason_code = row.unavailable_reason_code;
            let action_title = row
                .unavailable_reason
                .as_deref()
                .map(|reason| translate_unavailable_reason(reason_code, reason))
                .unwrap_or_else(|| t!("download-action-title"));
            (row, action_title)
        })
        .collect::<Vec<_>>();
    let document_count = loaded.report.document_count as i64;
    let downloadable_count_arg = downloadable_count as i64;
    let unsupported_count_arg = unsupported_count as i64;
    let error_count = loaded.report.errors.len() as i64;
    let warning_count = loaded.report.warnings.len() as i64;

    rsx! {
        section { class: "min-w-0 rounded-box border border-base-300 bg-base-100 shadow-sm",
            div { class: "space-y-5 p-5 sm:p-6",
                div { class: "flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between",
                    div { class: "min-w-0",
                        p { class: "text-xs font-semibold uppercase tracking-wide text-base-content/55", { t!("loaded-eyebrow") } }
                        h2 { class: "mt-1 break-words text-xl font-semibold tracking-tight", "{loaded.file_name}" }
                        p { class: "mt-1 text-sm text-base-content/70", { t!("loaded-body") } }
                    }
                    button {
                        class: "btn btn-primary min-h-11",
                        disabled: downloadable_count == 0,
                        title: "{download_all_title}",
                        onclick: move |_| {
                            download_all_supported(loaded.clone(), notice, i18n);
                        },
                        { t!("download-supported") }
                    }
                }

                dl { class: "grid overflow-hidden rounded-box border border-base-300 bg-base-200/60 text-sm sm:grid-cols-4",
                    div { class: "border-b border-base-300 p-3 sm:border-b-0 sm:border-r",
                        dt { class: "text-base-content/60", { t!("summary-documents-label") } }
                        dd { class: "mt-1 font-medium", { t!("summary-documents-value", count: document_count) } }
                    }
                    div { class: "border-b border-base-300 p-3 sm:border-b-0 sm:border-r",
                        dt { class: "text-base-content/60", { t!("summary-supported-label") } }
                        dd { class: "mt-1 font-medium", { t!("summary-supported-value", count: downloadable_count_arg) } }
                    }
                    div { class: "border-b border-base-300 p-3 sm:border-b-0 sm:border-r",
                        dt { class: "text-base-content/60", { t!("summary-unavailable-label") } }
                        dd { class: "mt-1 font-medium", { t!("summary-unavailable-value", count: unsupported_count_arg) } }
                    }
                    div { class: "p-3",
                        dt { class: "text-base-content/60", { t!("summary-findings-label") } }
                        dd { class: "mt-1 font-medium", { t!("summary-findings-value", errors: error_count, warnings: warning_count) } }
                    }
                }

                if !loaded.report.errors.is_empty() {
                    div { class: "alert alert-error items-start", role: "alert",
                        div {
                            h3 { class: "font-semibold", { t!("findings-errors-title") } }
                            ul { class: "mt-2 list-disc space-y-1 pl-5 text-sm",
                                for finding in &loaded.report.errors {
                                    li { "{finding.message}" }
                                }
                            }
                        }
                    }
                }

                if !loaded.report.warnings.is_empty() {
                    div { class: "alert alert-warning items-start", role: "status",
                        div {
                            h3 { class: "font-semibold", { t!("findings-warnings-title") } }
                            ul { class: "mt-2 list-disc space-y-1 pl-5 text-sm",
                                for finding in &loaded.report.warnings {
                                    li { "{finding.message}" }
                                }
                            }
                        }
                    }
                }

                div { class: "w-full overflow-x-auto rounded-box border border-base-300 bg-base-100",
                    table { class: "table table-zebra min-w-[64rem]",
                        caption { class: "sr-only", { t!("table-caption", filename: loaded.file_name.as_str()) } }
                        thead {
                            tr {
                                th { "#" }
                                th { { t!("table-title") } }
                                th { { t!("table-filename") } }
                                th { { t!("table-mime") } }
                                th { { t!("table-size") } }
                                th { { t!("table-transforms") } }
                                th { { t!("table-signature-metadata") } }
                                th { class: "sticky right-0 z-10 border-l border-base-300 bg-base-100", { t!("table-action") } }
                            }
                        }
                        tbody {
                            for (row, action_title) in rows_for_table {
                                tr {
                                    td { class: "text-base-content/65", "{row.index}" }
                                    td { class: "max-w-xs whitespace-normal font-medium", "{row.title}" }
                                    td { code { class: "block max-w-xs whitespace-pre-wrap break-words rounded bg-base-200 px-1.5 py-1 font-mono text-xs", "{row.filename}" } }
                                    td { span { class: "badge badge-outline whitespace-nowrap", "{row.mime_type}" } }
                                    td { class: "whitespace-nowrap", "{row.source_size} B" }
                                    td { class: "max-w-xs whitespace-normal text-sm text-base-content/75", "{row.transforms}" }
                                    td {
                                        div { class: "flex flex-wrap gap-1",
                                            span { class: "badge badge-ghost", { t!("signature-count", count: row.signature_count as i64) } }
                                            span { class: "badge badge-ghost", { t!("timestamp-count", count: row.timestamp_count as i64) } }
                                        }
                                    }
                                    td { class: "sticky right-0 border-l border-base-300 bg-base-100",
                                        button {
                                            class: "btn btn-outline btn-primary btn-sm min-h-11",
                                            title: "{action_title}",
                                            disabled: !row.can_download,
                                            onclick: {
                                                let loaded = loaded.clone();
                                                let index = row.index;
                                                move |_| {
                                                    let loaded = loaded.clone();
                                                    spawn(async move {
                                                        match session::extract_for_download(&loaded, index) {
                                                            Ok(file) => notice.set(Some(single_download_notice(i18n, &file, download::download_bytes(&file.filename, &file.bytes)))),
                                                            Err(error) => notice.set(Some(error)),
                                                        }
                                                    });
                                                }
                                            },
                                            { t!("download-button") }
                                        }
                                        if let Some(reason) = row.unavailable_reason.as_ref() {
                                            div { class: "mt-2 max-w-40 text-xs leading-snug text-base-content/65", { translate_unavailable_reason(row.unavailable_reason_code, reason) } }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn single_download_notice(
    i18n: I18n,
    file: &DownloadFile,
    outcome: Result<DownloadOutcome, String>,
) -> String {
    match outcome {
        Ok(DownloadOutcome::Requested) => translate_string_arg(
            i18n,
            "notice-download-requested",
            "filename",
            &file.filename,
        ),
        Err(error) => session::download_failure(&file.filename, &error),
    }
}

fn request_browser_downloads(
    files: Vec<DownloadFile>,
    mut request_download: impl FnMut(&DownloadFile) -> Result<DownloadOutcome, String>,
    mut failures: Vec<String>,
    i18n: I18n,
) -> String {
    let file_count = files.len();
    let mut requested_count = 0usize;

    for file in files {
        match request_download(&file) {
            Ok(DownloadOutcome::Requested) => {
                requested_count += 1;
            }
            Err(error) => failures.push(session::download_failure(&file.filename, &error)),
        }
    }

    browser_download_all_notice(i18n, file_count, requested_count, failures)
}

fn browser_download_all_notice(
    i18n: I18n,
    file_count: usize,
    requested_count: usize,
    failures: Vec<String>,
) -> String {
    if failures.is_empty() && requested_count == file_count {
        i18n.translate("notice-browser-downloads-all")
    } else {
        success_or_failures_message(
            requested_count,
            translate_count_arg(
                i18n,
                "notice-browser-downloads-partial",
                "count",
                requested_count,
            ),
            failures,
        )
    }
}

fn translate_no_supported_notice(i18n: I18n, message: String) -> String {
    if message == session::no_supported_files_notice(&[]) {
        i18n.translate("notice-no-supported-files")
    } else {
        message
    }
}

fn translate_unavailable_reason(
    reason_code: Option<ExtractionUnavailableReason>,
    fallback: &str,
) -> String {
    match reason_code {
        Some(ExtractionUnavailableReason::EncryptedDocument) => t!("unavailable-encrypted"),
        None => fallback.to_owned(),
    }
}

fn translate_string_arg(i18n: I18n, key: &str, name: &'static str, value: &str) -> String {
    let mut args = FluentArgs::new();
    args.set(name, value);
    i18n.translate_with_args(key, Some(&args))
}

fn translate_count_arg(i18n: I18n, key: &str, name: &'static str, count: usize) -> String {
    let mut args = FluentArgs::new();
    args.set(name, count as i64);
    i18n.translate_with_args(key, Some(&args))
}

fn success_or_failures_message(
    count: usize,
    success_message: String,
    failures: Vec<String>,
) -> String {
    match (count, failures.is_empty()) {
        (_, true) => success_message,
        (0, false) => failures.join("; "),
        (_, false) => format!("{} {}", success_message, failures.join("; ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_language_accepts_only_available_locales() {
        assert_eq!(supported_language("en-US"), Some(EN_US.clone()));
        assert_eq!(supported_language("hu-HU"), Some(HU_HU.clone()));
        assert_eq!(supported_language("de-DE"), None);
    }
}
