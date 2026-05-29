#![allow(dead_code)]

pub fn xml_with_document(title: &str, payload: &str, transforms: &[&str]) -> String {
    let transform_xml = transforms
        .iter()
        .map(|algorithm| format!("<es:Transform Algorithm=\"{algorithm}\"/>"))
        .collect::<String>();

    format!(
        r##"<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <es:DossierProfile Id="Profile0" OBJREF="#Object0"><es:Title>Dossier</es:Title><es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate></es:DossierProfile>
  <es:Documents Id="Object0">
    <es:Document>
      <es:DocumentProfile Id="Profile1" OBJREF="#Payload1">
        <es:Title>{title}</es:Title>
        <es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="text" subtype="plain" extension="txt"/></es:Format>
        <es:SourceSize sizeValue="11" sizeUnit="B"/>
        <es:BaseTransform>{transform_xml}</es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="Payload1">{payload}</ds:Object>
    </es:Document>
  </es:Documents>
</es:Dossier>"##
    )
}

pub fn xml_with_transform(title: &str, transforms: &[&str]) -> String {
    xml_with_document(title, "SGVsbG8gd29ybGQ=", transforms)
}

pub fn xml_with_two_documents() -> String {
    r##"<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <es:DossierProfile Id="Profile0" OBJREF="#Object0"><es:Title>Dossier</es:Title><es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate></es:DossierProfile>
  <es:Documents Id="Object0">
    <es:Document>
      <es:DocumentProfile Id="Profile1" OBJREF="#Payload1">
        <es:Title>Plain</es:Title>
        <es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="text" subtype="plain" extension="txt"/></es:Format>
        <es:SourceSize sizeValue="11" sizeUnit="B"/>
        <es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="Payload1">SGVsbG8gd29ybGQ=</ds:Object>
    </es:Document>
    <es:Document>
      <es:DocumentProfile Id="Profile2" OBJREF="#Payload2">
        <es:Title>Secret</es:Title>
        <es:CreationDate>2026-05-16T00:00:00Z</es:CreationDate>
        <es:Format><es:MIME-Type type="text" subtype="plain" extension="txt"/></es:Format>
        <es:SourceSize sizeValue="11" sizeUnit="B"/>
        <es:BaseTransform><es:Transform Algorithm="encrypt"/><es:Transform Algorithm="base64"/></es:BaseTransform>
      </es:DocumentProfile>
      <ds:Object Id="Payload2">SGVsbG8gd29ybGQ=</ds:Object>
    </es:Document>
  </es:Documents>
</es:Dossier>"##
        .to_owned()
}
