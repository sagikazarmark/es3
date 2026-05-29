use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{fmt, fs};

use clap::{Parser, Subcommand, ValueEnum};
use es3::{
    Dossier, Error, ExtractedDocument, SignatureScope, StructureReport, ValidationLayerStatus,
    VerificationOptions, VerificationReport,
};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List documents in an ES3 dossier.
    List {
        file: PathBuf,

        /// Print document metadata as pretty JSON.
        #[arg(long)]
        json: bool,
    },

    /// Extract documents from an ES3 dossier.
    Extract {
        file: PathBuf,

        /// Output directory.
        #[arg(long)]
        output: PathBuf,

        /// Extract only the document at this zero-based index.
        #[arg(long, conflicts_with = "title")]
        index: Option<usize>,

        /// Extract only the document with this exact title.
        #[arg(long, conflicts_with = "index")]
        title: Option<String>,

        /// Replace existing output files atomically.
        #[arg(long)]
        overwrite: bool,
    },

    /// Verify an ES3 dossier.
    Verify {
        file: PathBuf,

        /// Print the verification report as pretty JSON.
        #[arg(long)]
        json: bool,

        /// Only check dossier structure; skip signature and certificate checks.
        #[arg(long)]
        structure_only: bool,

        /// Require each checked signature to use this exact signer certificate.
        #[arg(long = "pinned-cert")]
        pinned_certificates: Vec<PathBuf>,

        /// Trust this certificate as an offline chain-validation anchor.
        #[arg(long = "trusted-anchor")]
        trusted_anchor_certificates: Vec<PathBuf>,

        /// Choose which signatures to check.
        #[arg(
            long = "check-signatures",
            value_enum,
            default_value = "all",
            help = "Choose which signatures to check: all, dossier-level, or embedded-document signatures"
        )]
        signature_selection: CliSignatureSelection,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSignatureSelection {
    #[value(alias = "frame")]
    Dossier,
    #[value(alias = "document")]
    Documents,
    All,
}

impl From<CliSignatureSelection> for SignatureScope {
    fn from(selection: CliSignatureSelection) -> Self {
        match selection {
            CliSignatureSelection::Dossier => Self::Dossier,
            CliSignatureSelection::Documents => Self::Document,
            CliSignatureSelection::All => Self::All,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::VerifyFailed) => ExitCode::from(1),
        Err(error) => {
            eprintln!("error: {error}");
            if matches!(error, CliError::ReadFile { .. }) {
                ExitCode::from(2)
            } else {
                ExitCode::from(1)
            }
        }
    }
}

fn run() -> Result<(), CliError> {
    match Cli::parse().command {
        Command::List { file, json } => list(file, json),
        Command::Extract {
            file,
            output,
            index,
            title,
            overwrite,
        } => extract(file, output, index, title, overwrite),
        Command::Verify {
            file,
            json,
            structure_only,
            pinned_certificates,
            trusted_anchor_certificates,
            signature_selection,
        } => verify(
            file,
            json,
            structure_only,
            pinned_certificates,
            trusted_anchor_certificates,
            signature_selection,
        ),
    }
}

fn list(file: PathBuf, json: bool) -> Result<(), CliError> {
    let dossier = read_dossier(&file)?;
    let documents = dossier.documents();

    if json {
        println!("{}", serde_json::to_string_pretty(&documents)?);
        return Ok(());
    }

    println!("INDEX\tTITLE\tMIME\tSIZE\tTRANSFORMS\tEXTRACTION\tSIGNATURES\tTIMESTAMPS");
    for document in documents {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            document.index(),
            serde_json::to_string(document.title())?,
            serde_json::to_string(&document.mime_type().to_string())?,
            document.source_size(),
            transform_list(document.transforms()),
            serde_json::to_string(extraction_label(document.extraction()))?,
            document.signature_count(),
            document.timestamp_count()
        );
    }

    Ok(())
}

fn extract(
    file: PathBuf,
    output: PathBuf,
    index: Option<usize>,
    title: Option<String>,
    overwrite: bool,
) -> Result<(), CliError> {
    let dossier = read_dossier(&file)?;
    let documents = match (index, title) {
        (Some(index), None) => vec![dossier.extract_document(index)?],
        (None, Some(title)) => vec![dossier.extract_document_by_title(&title)?],
        (None, None) => dossier
            .documents()
            .into_iter()
            .map(|document| dossier.extract_document(document.index()))
            .collect::<std::result::Result<Vec<_>, Error>>()?,
        (Some(_), Some(_)) => unreachable!("clap rejects conflicting options"),
    };
    let paths = write_extracted_documents(&output, &documents, overwrite)?;

    for path in paths {
        println!("{}", path.display());
    }

    Ok(())
}

fn verify(
    file: PathBuf,
    json: bool,
    structure_only: bool,
    pinned_certificates: Vec<PathBuf>,
    trusted_anchor_certificates: Vec<PathBuf>,
    signature_selection: CliSignatureSelection,
) -> Result<(), CliError> {
    let xml = read_xml(&file)?;

    if structure_only {
        let report = es3::verify_str(&xml, VerificationOptions::without_signatures());

        if json {
            println!("{}", serde_json::to_string_pretty(&report.structure)?);
        } else {
            print_human_structure_report(&report.structure);
        }

        return if report.structure.is_ok() {
            Ok(())
        } else {
            Err(CliError::VerifyFailed)
        };
    }

    let mut options = VerificationOptions::default()
        .with_signature_scope(SignatureScope::from(signature_selection));
    for certificate in pinned_certificates {
        options = options.with_pinned_certificate(read_binary(&certificate)?);
    }
    for certificate in trusted_anchor_certificates {
        options = options.with_trusted_anchor_certificate(read_binary(&certificate)?);
    }
    let report = es3::verify_str(&xml, options);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_verification_report(&report);
    }

    if report.checked_layers_ok() {
        Ok(())
    } else {
        Err(CliError::VerifyFailed)
    }
}

fn read_xml(file: &PathBuf) -> Result<String, CliError> {
    fs::read_to_string(file).map_err(|source| CliError::ReadFile {
        path: file.clone(),
        source,
    })
}

fn read_dossier(file: &PathBuf) -> Result<Dossier, CliError> {
    let xml = read_xml(file)?;
    xml.parse::<Dossier>().map_err(CliError::Runtime)
}

fn read_binary(file: &PathBuf) -> Result<Vec<u8>, CliError> {
    fs::read(file).map_err(|source| CliError::ReadFile {
        path: file.clone(),
        source,
    })
}

fn write_extracted_documents(
    output: &Path,
    documents: &[ExtractedDocument],
    overwrite: bool,
) -> Result<Vec<PathBuf>, CliError> {
    let mut writer = DirectoryOutput::new(output, overwrite);

    documents
        .iter()
        .map(|document| writer.write(&document.filename, &document.bytes))
        .collect::<std::result::Result<Vec<_>, _>>()
}

struct DirectoryOutput<'a> {
    overwrite: bool,
    directory: &'a Path,
    used: HashSet<String>,
}

impl<'a> DirectoryOutput<'a> {
    fn new(directory: &'a Path, overwrite: bool) -> Self {
        Self {
            overwrite,
            directory,
            used: HashSet::new(),
        }
    }

    fn write(&mut self, filename: &str, bytes: &[u8]) -> Result<PathBuf, CliError> {
        fs::create_dir_all(self.directory).map_err(|source| CliError::CreateDir {
            path: self.directory.to_path_buf(),
            source,
        })?;

        let path = self.next_path(filename);
        let output_dir = path.parent().unwrap_or_else(|| Path::new("."));

        if self.overwrite {
            write_via_temp_file(&path, output_dir, bytes)?;
        } else {
            write_new_file(&path, bytes)?;
        }

        Ok(path)
    }

    fn next_path(&mut self, filename: &str) -> PathBuf {
        let safe_name = safe_leaf_filename(filename, "document");
        let (stem, extension) = split_extension(&safe_name, "document");

        for duplicate_index in 0usize.. {
            let candidate = cli_candidate_name(&safe_name, stem, extension, duplicate_index);
            if self.used.insert(candidate.clone()) {
                return self.directory.join(candidate);
            }
        }

        unreachable!()
    }
}

fn cli_candidate_name(
    safe_name: &str,
    stem: &str,
    extension: Option<&str>,
    duplicate_index: usize,
) -> String {
    match (duplicate_index, extension) {
        (0, _) => safe_name.to_owned(),
        (index, Some(extension)) => format!("{stem}-{}.{extension}", index + 1),
        (index, None) => format!("{stem}-{}", index + 1),
    }
}

fn safe_leaf_filename(filename: &str, fallback: &str) -> String {
    Path::new(filename)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(fallback)
        .to_owned()
}

fn split_extension<'a>(filename: &'a str, fallback: &'a str) -> (&'a str, Option<&'a str>) {
    let path = Path::new(filename);
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or(fallback);
    let extension = path.extension().and_then(|extension| extension.to_str());

    (stem, extension)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| match source.kind() {
            ErrorKind::AlreadyExists => CliError::OutputExists(path.to_path_buf()),
            _ => CliError::WriteFile {
                path: path.to_path_buf(),
                source,
            },
        })?;

    file.write_all(bytes).map_err(|source| CliError::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

fn write_via_temp_file(path: &Path, output_dir: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut last_error = None;

    for attempt in 0..1000u32 {
        let temp_path = output_dir.join(format!(
            ".{}.{}.{}.tmp",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("extract"),
            std::process::id(),
            attempt
        ));

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(mut file) => {
                if let Err(source) = file.write_all(bytes) {
                    let _ = fs::remove_file(&temp_path);
                    return Err(CliError::WriteFile {
                        path: temp_path,
                        source,
                    });
                }

                if let Err(source) = fs::rename(&temp_path, path) {
                    let _ = fs::remove_file(&temp_path);
                    return Err(CliError::WriteFile {
                        path: path.to_path_buf(),
                        source,
                    });
                }

                return Ok(());
            }
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {
                last_error = Some(source);
            }
            Err(source) => {
                return Err(CliError::WriteFile {
                    path: temp_path,
                    source,
                });
            }
        }
    }

    Err(CliError::WriteFile {
        path: output_dir.to_path_buf(),
        source: last_error.unwrap_or_else(|| ErrorKind::AlreadyExists.into()),
    })
}

fn print_human_structure_report(report: &StructureReport) {
    println!("ES3 structural verification report (not cryptographic)");
    println!("documents: {}", report.document_count);
    println!("document signatures: {}", report.document_signature_count);
    println!("document timestamps: {}", report.document_timestamp_count);
    println!("dossier signatures: {}", report.dossier_signature_count);
    println!("dossier timestamps: {}", report.dossier_timestamp_count);

    if report.errors.is_empty() {
        println!("errors: none");
    } else {
        println!("errors:");
        for finding in &report.errors {
            println!(
                "- {}",
                finding_message(finding.document_index, &finding.message)
            );
        }
    }

    if report.warnings.is_empty() {
        println!("warnings: none");
    } else {
        println!("warnings:");
        for finding in &report.warnings {
            println!(
                "- {}",
                finding_message(finding.document_index, &finding.message)
            );
        }
    }
}

fn print_human_verification_report(report: &VerificationReport) {
    println!("ES3 verification report");
    println!(
        "structural: {}",
        validation_status(report.validation.structural)
    );
    println!(
        "cryptographic: {}",
        validation_status(report.validation.cryptographic)
    );
    println!("trust: {}", validation_status(report.validation.trust));
    println!("documents: {}", report.structure.document_count);
    println!(
        "document signatures: {}",
        report.structure.document_signature_count
    );
    println!(
        "dossier signatures: {}",
        report.structure.dossier_signature_count
    );

    match &report.signatures {
        None => println!("signatures: not checked"),
        Some(signatures) => {
            println!("checked signatures: {}", signatures.signature_count);
            for signature in &signatures.signatures {
                let id = signature.id.as_deref().unwrap_or("<none>");
                println!(
                    "- {} {id}: signature_value={}, trust={}",
                    signature_scope_label(signature.scope),
                    if signature.signature_value_valid {
                        "valid"
                    } else {
                        "invalid"
                    },
                    validation_status(signature.trust)
                );
                if let Some(certificate) = &signature.signer_certificate {
                    println!("  signer: {}", certificate.subject);
                    println!("  issuer: {}", certificate.issuer);
                    println!("  signer cert sha256: {}", certificate.sha256_fingerprint);
                    println!(
                        "  XAdES signing certificate: {:?}",
                        signature.xades_signing_certificate
                    );
                }
                if signature.evidence.timestamp_count > 0
                    || signature.evidence.ocsp_value_count > 0
                    || signature.evidence.certificate_value_count > 0
                    || signature.evidence.crl_value_count > 0
                {
                    println!(
                        "  evidence: timestamps={}, certificates={}, ocsp={}, crl={}",
                        signature.evidence.timestamp_count,
                        signature.evidence.certificate_value_count,
                        signature.evidence.ocsp_value_count,
                        signature.evidence.crl_value_count
                    );
                }
            }
        }
    }

    print_findings("structural errors", &report.structure.errors);
    print_findings("structural warnings", &report.structure.warnings);

    if let Some(signatures) = &report.signatures {
        if signatures.errors.is_empty() {
            println!("signature errors: none");
        } else {
            println!("signature errors:");
            for finding in &signatures.errors {
                let id = finding.signature_id.as_deref().unwrap_or("<none>");
                println!("- {id}: {}", finding.message);
            }
        }

        if signatures.warnings.is_empty() {
            println!("signature warnings: none");
        } else {
            println!("signature warnings:");
            for finding in &signatures.warnings {
                let id = finding.signature_id.as_deref().unwrap_or("<none>");
                println!("- {id}: {}", finding.message);
            }
        }
    }
}

fn signature_scope_label(scope: SignatureScope) -> &'static str {
    match scope {
        SignatureScope::Dossier => "dossier-level signature",
        SignatureScope::Document => "embedded-document signature",
        SignatureScope::All => "signature",
    }
}

fn validation_status(status: ValidationLayerStatus) -> &'static str {
    match status {
        ValidationLayerStatus::NotChecked => "not checked",
        ValidationLayerStatus::Passed => "passed",
        ValidationLayerStatus::Failed => "failed",
    }
}

fn print_findings(label: &str, findings: &[es3::Finding]) {
    if findings.is_empty() {
        println!("{label}: none");
    } else {
        println!("{label}:");
        for finding in findings {
            println!(
                "- {}",
                finding_message(finding.document_index, &finding.message)
            );
        }
    }
}

fn finding_message(document_index: Option<usize>, message: &str) -> String {
    match document_index {
        Some(index) => format!("document {index}: {message}"),
        None => message.to_owned(),
    }
}

fn transform_list(transforms: &[es3::Transform]) -> String {
    if transforms.is_empty() {
        "-".to_owned()
    } else {
        transforms
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn extraction_label(extraction: &es3::ExtractionCapability) -> &str {
    extraction.unavailable_reason().unwrap_or("available")
}

#[derive(Debug)]
enum CliError {
    Runtime(Error),
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    OutputExists(PathBuf),
    Json(serde_json::Error),
    VerifyFailed,
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => write!(formatter, "{error}"),
            Self::ReadFile { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::WriteFile { path, source } => {
                write!(formatter, "failed to write {}: {source}", path.display())
            }
            Self::CreateDir { path, source } => write!(
                formatter,
                "failed to create directory {}: {source}",
                path.display()
            ),
            Self::OutputExists(path) => {
                write!(formatter, "output file already exists: {}", path.display())
            }
            Self::Json(error) => write!(formatter, "failed to write JSON: {error}"),
            Self::VerifyFailed => formatter.write_str("verification failed"),
        }
    }
}

impl From<Error> for CliError {
    fn from(error: Error) -> Self {
        Self::Runtime(error)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
