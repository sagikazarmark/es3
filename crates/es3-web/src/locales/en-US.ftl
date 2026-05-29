app-title = Open es3 file
hero-description = Open electronic dossiers and signed documents.
privacy-card-title = Client-side file handling
privacy-card-body = Files are read by this app on your device. Dossier content never leaves your device.
language-switcher-label = Language
language-english = English
language-hungarian = Magyar
language-switch-to-english = Switch language to English
language-switch-to-hungarian = Switch language to Hungarian
file-card-title = Choose an ES3 file
file-picker-title = Select .es3 or .et3
file-picker-body = The selected file is read locally by this app.
error-no-file-selected = No file selected.
error-read-file = Could not read file: {$error}
empty-title = No dossier opened
empty-body = Select an ES3 dossier to list embedded files and extraction options.
empty-step-choose-title = 1. Choose
empty-step-choose-body = a local dossier file.
empty-step-inspect-title = 2. Inspect
empty-step-inspect-body = embedded documents.
empty-step-download-title = 3. Download
empty-step-download-body = supported files.
loading-title = Reading dossier
open-error-title = Could not open ES3 file
open-error-help = Check that the selected file is a readable ES3 or ET3 dossier.
download-all-title-none = No supported files are available to download
download-all-title-available = Request downloads for every supported embedded file
download-action-title = Download this embedded file
loaded-eyebrow = Opened dossier
loaded-body = Embedded documents are listed below with extraction status and structural findings.
download-supported = Download supported files
summary-documents-label = Documents
summary-documents-value =
    { $count ->
        [one] 1 listed
       *[other] {$count} listed
    }
summary-supported-label = Supported
summary-supported-value =
    { $count ->
        [one] 1 download
       *[other] {$count} downloads
    }
summary-unavailable-label = Unavailable
summary-unavailable-value =
    { $count ->
        [one] 1 file
       *[other] {$count} files
    }
summary-findings-label = Findings
summary-findings-value = {$errors} errors, {$warnings} warnings
findings-errors-title = Structural errors
findings-warnings-title = Structural warnings
table-caption = Embedded documents in {$filename}
table-title = Title
table-filename = Filename
table-mime = MIME
table-size = Size
table-transforms = Transforms
table-signature-metadata = Signature metadata
table-action = Action
signature-count =
    { $count ->
        [one] 1 signature
       *[other] {$count} signatures
    }
timestamp-count =
    { $count ->
        [one] 1 timestamp
       *[other] {$count} timestamps
    }
download-button = Download
unavailable-encrypted = Encrypted document extraction is not supported
notice-download-requested = Download request created for {$filename}.
notice-no-supported-files = No supported files are available to download.
notice-browser-downloads-all = Download requests were created for all supported files.
notice-browser-downloads-partial =
    { $count ->
        [one] Download request was created for 1 supported file.
       *[other] Download requests were created for {$count} supported files.
    }
