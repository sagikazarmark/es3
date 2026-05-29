use roxmltree::Node;

use crate::{Error, Result};

pub(crate) const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub(crate) const XML_PARSE_NODE_LIMIT: u32 = 4_096;
const XML_PARSE_MARKER_LIMIT: usize = XML_PARSE_NODE_LIMIT as usize;

pub(crate) fn parse_xml_document(xml: &str) -> Result<roxmltree::Document<'_>> {
    ensure_xml_marker_budget(xml.as_bytes())?;
    roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: XML_PARSE_NODE_LIMIT,
            entity_resolver: None,
        },
    )
    .map_err(Error::Xml)
}

fn ensure_xml_marker_budget(xml: &[u8]) -> Result<()> {
    let attribute_markers = xml.iter().filter(|byte| **byte == b'=').count();
    if attribute_markers > XML_PARSE_MARKER_LIMIT {
        return Err(Error::XmlAttributeMarkerLimitReached {
            markers: attribute_markers,
            limit: XML_PARSE_MARKER_LIMIT,
        });
    }
    Ok(())
}

pub(crate) fn is_es(node: Node<'_, '_>, name: &str) -> bool {
    node.is_element()
        && node.tag_name().name() == name
        && node.tag_name().namespace().is_some()
        && node.tag_name().namespace() != Some(DS_NS)
}

pub(crate) fn is_ds(node: Node<'_, '_>, name: &str) -> bool {
    node.is_element()
        && node.tag_name().name() == name
        && node.tag_name().namespace() == Some(DS_NS)
}

pub(crate) fn child_es<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    let namespace = node.tag_name().namespace();
    node.children()
        .find(|child| is_es_child(*child, name, namespace))
}

pub(crate) fn children_es<'a, 'input>(
    node: Node<'a, 'input>,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    let namespace = node.tag_name().namespace();
    node.children()
        .filter(move |child| is_es_child(*child, name, namespace))
}

pub(crate) fn children_ds<'a, 'input>(
    node: Node<'a, 'input>,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children().filter(move |child| is_ds(*child, name))
}

pub(crate) fn child_text(node: Node<'_, '_>, name: &str) -> Option<String> {
    child_es(node, name).map(|child| child.text().unwrap_or_default().to_owned())
}

pub(crate) fn document_profile_path(index: usize, suffix: &str) -> String {
    format!("Document[{index}]/{suffix}")
}

fn is_es_child(node: Node<'_, '_>, name: &str, namespace: Option<&str>) -> bool {
    node.is_element() && node.tag_name().name() == name && node.tag_name().namespace() == namespace
}
