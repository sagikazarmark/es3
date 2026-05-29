use crate::document::{DocumentEntry, MimeType};

pub(crate) fn filename_for(entry: &DocumentEntry) -> String {
    filename_from_parts(entry.index(), entry.title(), entry.mime_type())
}

fn filename_from_parts(index: usize, title: &str, mime_type: &MimeType) -> String {
    let mut filename = sanitize_stem(title);
    if filename.is_empty() {
        filename = format!("document-{index}");
    }

    if let Some(extension) = mime_type
        .extension()
        .map(sanitize_extension)
        .filter(|extension| !extension.is_empty())
    {
        filename.push('.');
        filename.push_str(&extension);
    }

    filename
}

fn sanitize_stem(value: &str) -> String {
    sanitize_component(value, false)
        .trim_matches(|character| character == ' ' || character == '.')
        .to_owned()
}

fn sanitize_extension(value: &str) -> String {
    sanitize_component(value.trim_start_matches('.'), true)
        .trim_matches(|character| character == ' ' || character == '.')
        .to_owned()
}

fn sanitize_component(value: &str, replace_spaces: bool) -> String {
    value
        .chars()
        .map(|character| {
            if is_unsafe_filename_character(character) || (replace_spaces && character == ' ') {
                '_'
            } else {
                character
            }
        })
        .collect()
}

fn is_unsafe_filename_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
        )
}
