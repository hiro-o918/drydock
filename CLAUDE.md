# Drydock - Artifact Registry Vulnerability Scanner

## Overview

Drydock is a CLI tool for scanning and reporting vulnerabilities from Google Cloud Artifact Registry. It allows users to query vulnerability information for container images and filter results by severity level.

## Architecture

The system consists of four main components. The **Image Resolver** acts as the discovery phase, determining the precise targets (Digests) before the **Analyzer** performs the scanning.

```
┌─────────────────┐
│                 │
│       CLI       │◀── (Orchestrator)
│                 │
└────────┬────────┘
         │
         │ 1. Resolve / Discover Targets
         ▼
┌─────────────────┐       2. Returns Digest(s)
│  Image Resolver │────────────────────────────────┐
│   (Discovery)   │                                │
└─────────────────┘                                │
                                                   │
         ┌─────────────────────────────────────────┘
         │
         │ 3. Analyze Vulnerabilities (per Digest)
         ▼
┌─────────────────┐       4. Returns Results
│    Analyzer     │────────────────────────────────┐
│  (Data Fetcher) │                                │
└─────────────────┘                                │
                                                   │
         ┌─────────────────────────────────────────┘
         │
         │ 5. Format & Output
         ▼
┌─────────────────┐
│    Exporter     │
│   (Formatter)   │
└─────────────────┘
```

### Component Responsibilities

1.  **CLI**: The entry point that orchestrates the workflow. It passes user input (tags, repo names, or project IDs) to the Resolver, receives a list of unique Digests, and then iterates over them to invoke the Analyzer.
2.  **Image Resolver**: **(New)** Responsible for target resolution and discovery.
    - **Current role:** Converts a mutable image tag (e.g., `latest`) into an immutable SHA256 digest.
    - **Future role:** Scans the entire project/repository to discover all images and identify the "latest" digest for every artifact, enabling bulk scanning.
3.  **Analyzer**: Strictly focuses on fetching vulnerability data. It accepts a specific **Digest** as input (isolating it from tag resolution logic) and queries the Artifact Registry/Container Analysis API.
4.  **Exporter**: Abstract interface for outputting the aggregated vulnerability results in various formats (JSON, Table, CSV).

### Workflow with Image Resolver

1.  **Input**: User provides a target (e.g., `my-image:latest` OR `projects/my-project`).
2.  **Resolution**:
    - The **CLI** calls **Image Resolver**.
    - If the input is a tag, Resolver calls `GetDockerImage` to find the Digest.
    - _(Future)_ If the input is a project, Resolver iterates through repositories to find the latest Digest for every image.
3.  **Analysis**: The CLI takes the resolved Digest(s) and passes them to the **Analyzer**.
4.  **Output**: Results are passed to the **Exporter**.

## Data Flow

1.  User executes CLI with parameters (project, repository, image, severity level, output format).
2.  CLI validates input and creates Config.
3.  **CLI instantiates Image Resolver to resolve the input tag/project to specific SHA256 Digest(s).**
4.  CLI instantiates Analyzer with appropriate credentials.
5.  **CLI selects and instantiates the appropriate Exporter based on output configuration (DI).**
6.  Analyzer connects to Artifact Registry API using the resolved Digest.
7.  Analyzer fetches vulnerability scan results.
8.  Analyzer filters and transforms data into `AnalyzeResult`.
9.  CLI invokes `Exporter.Export()` with the results.
10. Exporter formats and outputs the results to its configured destination.
11. CLI returns exit code (0 for success, non-zero for errors or if vulnerabilities found).

## Design Principles

### 1\. Flat Package Structure

- All components reside in the same package initially (package main).
- Follow Go best practices: start simple, split packages when necessary.
- Components are separated by clear interface boundaries.
- Package split can be done later if the codebase grows.

### 2\. Separation of Concerns

- **CLI** handles user interaction and orchestration.
- **Image Resolver** handles target discovery and tag resolution.
- **Analyzer** focuses on data fetching and processing.
- **Exporter** handles output formatting and destination.
- Clear separation through interfaces, not packages.

### 3\. Dependency Injection

- Exporter implementation is chosen at initialization time.
- Makes testing easier with mock implementations.
- Clear separation between configuration and execution.

### 4\. Interface-Driven Design

- All components are defined by interfaces.
- Enables easy testing with mock implementations.
- Allows for future extensions (e.g., support for other registries).

### 5\. Single Responsibility

- Each component has a clear, focused purpose.
- Components can be tested independently.
- Changes to one component minimize impact on others.

### 6\. Open/Closed Principle

- New export formats can be added by creating new implementations.
- Analyzer can be extended for different data sources.
- No modification to existing code needed for extensions.

### Extensibility Points

1.  **Multiple Registry Support**: The Analyzer interface can be extended to support Docker Hub, AWS ECR, etc.
2.  **Custom Filters**: Additional filtering logic beyond severity level.
3.  **Output Formats**: New exporters can be added for different formats (HTML, PDF, YAML, etc.).
4.  **Output Destinations**: Additional exporters for S3, Azure Blob Storage, etc.
5.  **Caching**: Cache vulnerability data to reduce API calls.
6.  **Continuous Monitoring**: Schedule periodic scans and track changes over time.
7.  **Policy Enforcement**: Define policies and fail builds based on vulnerability thresholds.
8.  **Notification Integration**: Exporters for Slack, email, PagerDuty, etc.

### Error Handling Strategy

- All components return errors following Go best practices.
- Context is used for cancellation and timeouts.
- Structured error types for different failure scenarios.
- Graceful degradation when possible.

### Testing Strategy

- **Logic-Focused Unit Tests**: Extract business logic (data transformation, filtering, summary calculation) into pure functions to isolate them from external API dependencies.
- **Internal Access via Bridge**: Use `export_test.go` to expose internal logic to the external test package (`_test`), enabling specific logic verification while maintaining the black-box testing structure.
- **Table-Driven Scenarios**: Use map-based table-driven tests (`map[string]struct`) with descriptive keys (e.g., "should ... when ...") to clearly define behavior and edge cases.
- **Structural Assertions**: Utilize `google/go-cmp` for declarative and readable deep equality checks of complex structs, removing the need for manual field-by-field assertions.
- **No API Mocking**: Skip complex mocking of third-party clients (Container Analysis API); focus strictly on verifying the processing logic that consumes the client output.
