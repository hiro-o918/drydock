# Drydock

**A lightweight CLI to audit container vulnerabilities in Google Cloud Artifact Registry.**

Drydock fetches vulnerability data directly from Google Cloud's Container Analysis API, allowing you to filter out noise and focus on High/Critical threats across your repositories.

## 🚀 Installation

### macOS & Linux (Recommended)

Run the following command to automatically download and install the latest binary.

**Default Installation (to `/usr/local/bin`):**

```bash
curl -sSfL https://raw.githubusercontent.com/hiro-o918/drydock/main/install.sh | sh
```

**Custom Installation Path:**
To install to a specific directory (e.g., local bin), set the `INSTALL_DIR` variable:

```bash
curl -sSfL https://raw.githubusercontent.com/hiro-o918/drydock/main/install.sh | INSTALL_DIR=$HOME/.local/bin sh
```

_(Make sure to add the target directory to your `$PATH`)_

### Go Install

If you have Go installed:

```bash
go install github.com/hiro-o918/drydock@latest
```

### Manual Download

You can also download the pre-built binary from the [Releases page](https://github.com/hiro-o918/drydock/releases).

## ⚡️ Usage

### Quick Start

Scan a location for **HIGH** and **CRITICAL** vulnerabilities (default behavior).

```bash
drydock -location us-central1
```

### Common Scenarios

**1. Find CRITICAL vulnerabilities only**
Focus on the most urgent threats.

```bash
drydock -location us-central1 -min-severity CRITICAL
```

**2. Export report to CSV**
Generate a spreadsheet-compatible file for reporting.

```bash
drydock -location us-central1 -output-format csv > report.csv
```

### Options

| Flag             | Description                                                     | Default |
| :--------------- | :-------------------------------------------------------------- | :------ |
| `-location`      | **(Required)** Artifact Registry location (e.g., `us-central1`) | -       |
| `-project`       | Google Cloud Project ID                          | current project from gcloud |
| `-min-severity`  | Filter by severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`         | `HIGH`  |
| `-output-format` | Output format: `json`, `csv`, `tsv`                             | `json`  |
| `-debug`         | Enable verbose logging                                          | `false` |

## 🔑 Prerequisites

Ensure you have the following configured before running:

1.  **Authentication:** Run `gcloud auth application-default login` or set `GOOGLE_APPLICATION_CREDENTIALS`.
2.  **Permissions:** Your account needs:
    - `roles/artifactregistry.reader` (To list images)
    - `roles/containeranalysis.occurrences.viewer` (To read vulnerability data)
