# Changelog

## [0.2.0](https://github.com/hiro-o918/drydock/compare/v0.1.0...v0.2.0) (2025-12-07)


### Features

* add --fixable-only flag to filter vulnerabilities with available ([89f19c8](https://github.com/hiro-o918/drydock/commit/89f19c846e5a5d85cde7a55ec1a8dd76dfb58bf9))
* Add concurrency support for container image scanning ([e12ed29](https://github.com/hiro-o918/drydock/commit/e12ed290cc3c6dc5f05fec5588d20d2bbfd32748))
* Add concurrency support for image scanning ([cae5c1d](https://github.com/hiro-o918/drydock/commit/cae5c1dd00540836ef0019c3504cd58a5d4f96ad))
* Add filter for fixable vulnerabilities only ([ffd83f8](https://github.com/hiro-o918/drydock/commit/ffd83f8ec2d1749af35d11fe6d064740f4a56fdf))
* Add fixable filter to ArtifactRegistryAnalyzer ([bacdb67](https://github.com/hiro-o918/drydock/commit/bacdb67cca74b60da33c95b4c5e3b2f6aa378ff4))


### Bug Fixes

* get tag for resolved image targets if available ([1769703](https://github.com/hiro-o918/drydock/commit/17697035dccd5a1bb62feeb052c5d8b90babcdfe))
* get tag for resolved image targets if available ([07ad326](https://github.com/hiro-o918/drydock/commit/07ad326dd4bb9f74d4c069e4330b659eec9958be))
* set default GCP project ID from environment in Drydock scanner ([0950230](https://github.com/hiro-o918/drydock/commit/09502306a5b83b306da39d9baa56185d13a6e64c))
* set default GCP project ID from environment in Drydock scanner ([f37d7b6](https://github.com/hiro-o918/drydock/commit/f37d7b65f2d31a46a7191664bef7df8145663cd0))


### Documentation

* add concurrency option and clarify project ID usage in README ([a7ba306](https://github.com/hiro-o918/drydock/commit/a7ba306a999795ff7cb3449c4076e38a96fd1540))
* Add fixable filter to README examples ([4e943e9](https://github.com/hiro-o918/drydock/commit/4e943e9e509d8844bc4d1c72727e54ecceb5920e))
* add top icon ([62252ae](https://github.com/hiro-o918/drydock/commit/62252aef030af21e9a835bf5818fd49b40bef844))


### Miscellaneous

* Add debug logging for vulnerability severity filtering ([6be9001](https://github.com/hiro-o918/drydock/commit/6be90019e86106fb66f52c5bb81ee573add4e1ce))

## [0.1.0](https://github.com/hiro-o918/drydock/compare/v0.0.2...v0.1.0) (2025-12-07)


### Features

* Add install script for drydock ([81ef425](https://github.com/hiro-o918/drydock/commit/81ef42552e3d53787f5b1d4e1bae443812c70de8))
* add package type to result ([a199b5e](https://github.com/hiro-o918/drydock/commit/a199b5ee4bc5d2f0d4c34c70af1e93f06c1ed995))
* add PackageType to vulnerability schema and export ([289420f](https://github.com/hiro-o918/drydock/commit/289420f93a2eec7d746ac92f5d1f9898936735c5))


### Documentation

* add installation and usage ([6d28202](https://github.com/hiro-o918/drydock/commit/6d282027c35b96ea74756b4f4f77f22df080ba3b))
* add installation and usage instructions to README.md ([5587e6f](https://github.com/hiro-o918/drydock/commit/5587e6f26d65b94c8d52f9bd924e35eb84ab29b2))

## [0.0.2](https://github.com/hiro-o918/drydock/compare/v0.1.0...v0.0.2) (2025-12-07)


### Features

* Add Artifact Registry Analyzer for vulnerability scanning ([c4e678b](https://github.com/hiro-o918/drydock/commit/c4e678bedc68b3352685001ce7ce87b220622a06))
* add cli configurations ([a7f222f](https://github.com/hiro-o918/drydock/commit/a7f222f748537af65303db062181e204b0a1c660))
* add CLI implementation with JSON export ([11d56e4](https://github.com/hiro-o918/drydock/commit/11d56e483143dd398316edc7691317df3e8a4924))
* add generic optional utilities IsZero and ToPtr ([e1f7d78](https://github.com/hiro-o918/drydock/commit/e1f7d78ddfec8f778f6ef9d82b9a62da0503de3e))
* Add ImageResolver for Docker image tag resolution ([4a62d29](https://github.com/hiro-o918/drydock/commit/4a62d292f86c0abc0179c6bfbfc3f6bf2c181dbd))
* Add ImageResolver for Docker image tag resolution ([5bb5a8d](https://github.com/hiro-o918/drydock/commit/5bb5a8dc317e52e2a008fc9f7e4628e7baf10c45))
* add interfaces for drydock ([496a9c6](https://github.com/hiro-o918/drydock/commit/496a9c6079093c10d1ffd6a2cc0d733b274af0ba))
* Add JSON exporter for analysis results ([1e66736](https://github.com/hiro-o918/drydock/commit/1e66736c9f85b04596b23d64f40ad09ecc195749))
* Add JSON repository and location to ImageTarget ([fc66a26](https://github.com/hiro-o918/drydock/commit/fc66a26af040b2e71439d6da26f6115c1ec94487))
* add JSON/YAML serialization tags to export types ([4e07895](https://github.com/hiro-o918/drydock/commit/4e07895520f17a08276d5924aff500baefbb8129))
* add JSON/YAML serialization tags to export types ([b9a0587](https://github.com/hiro-o918/drydock/commit/b9a0587d0ffd2b71583840522095e835c2c1d4a3))
* add linting and formatting configuration ([947340a](https://github.com/hiro-o918/drydock/commit/947340a0361e9e3cbd7fae445965ad260b09b0d7))
* Add Table Exporter for CSV/TSV Formats ([2bad770](https://github.com/hiro-o918/drydock/commit/2bad77020cff6d645f902ed4af1d3821f0481860))
* Add table exporter support and refactor exporter initialization ([c62b31a](https://github.com/hiro-o918/drydock/commit/c62b31aeec9837f5b2092ee4879a648e08d0ea06))
* Add table exporter support for CSV/TSV formats ([ceb57a1](https://github.com/hiro-o918/drydock/commit/ceb57a135b63507f08a79514e91ca1ed437fcc25))
* Enhance Table Exporter with Artifact Details ([c58c6a6](https://github.com/hiro-o918/drydock/commit/c58c6a6db1c7c51bcd0e146083178b8f899a9a07))
* Enhance Table Exporter with Artifact Details ([5a19d46](https://github.com/hiro-o918/drydock/commit/5a19d462b232601aadbd6d4608f7ac0ca951700c))
* implement analyzer ([a1f810e](https://github.com/hiro-o918/drydock/commit/a1f810e46185afeabc1d8067a959d731a6db6323))
* initialize project and stubs ([e9e18f7](https://github.com/hiro-o918/drydock/commit/e9e18f7c959ca5928c6967579b45def55061e140))
* setup ci ([d8c9132](https://github.com/hiro-o918/drydock/commit/d8c9132ade085a999cd00d9cf9b8da66f2d388bf))


### Documentation

* add CLAUDE.md ([2d8e85a](https://github.com/hiro-o918/drydock/commit/2d8e85a514149be4048de0e12dbc6302f2161be5))
* simplify CLAUDE.md ([e7d5e26](https://github.com/hiro-o918/drydock/commit/e7d5e26bbfc06c1d962ac7469b41ec5d922561f2))


### Miscellaneous

* add dependencies for analyzer ([492bfe1](https://github.com/hiro-o918/drydock/commit/492bfe178d17c71872b0662345e7530511986468))
* delete main_test.go ([e180436](https://github.com/hiro-o918/drydock/commit/e1804363d48c486487307d00c902f35ebd17c03b))
* force release v0.0.1 ([380986c](https://github.com/hiro-o918/drydock/commit/380986ce3ae702ffd207c3351513153eb346c12b))
* force release v0.0.2 ([0c3eb7e](https://github.com/hiro-o918/drydock/commit/0c3eb7e46fc2827a5bf29ceb8c398db131c1f07b))
* **main:** release 0.0.1 ([20b253b](https://github.com/hiro-o918/drydock/commit/20b253b4499efafffb09dcf628c9a62fa352fb01))
* **main:** release 0.2.0 ([46dbb45](https://github.com/hiro-o918/drydock/commit/46dbb455c48aab67da07efed63040ea9e6faa646))
* remove unused configs.go file ([de9784f](https://github.com/hiro-o918/drydock/commit/de9784f15dcb40b3cae11147a9d062ae9ffede9d))
* remove unused types ([fc33f4e](https://github.com/hiro-o918/drydock/commit/fc33f4ef577b5831e789c60a1818b3ee7578ee6d))
* run pinact ([abdad16](https://github.com/hiro-o918/drydock/commit/abdad161e40133804b117f9ae98011ed5f1170e5))
* setup GoReleaser workflow for tags ([fed0f19](https://github.com/hiro-o918/drydock/commit/fed0f198da8c69cb14209c0998e25d5a0f6575ed))
* setup logger with zerolog ([361e531](https://github.com/hiro-o918/drydock/commit/361e531f3def2ad2b878d76033de63a199c1020d))
* update .gitignore ([49ffcb7](https://github.com/hiro-o918/drydock/commit/49ffcb7687093d230aa7e401a0c306a07807b2bd))
* update CLAUDE.md ([ac64152](https://github.com/hiro-o918/drydock/commit/ac64152dad991b3cb21e171821e3db9ebb930305))


### Tests

* accept lowercase severity in tests ([65e6574](https://github.com/hiro-o918/drydock/commit/65e657484a061e93b2bcd4d3c4b65a1b028f97b1))


### CI/CD

* add GitHub Actions workflow for testing and linting ([6f69f8e](https://github.com/hiro-o918/drydock/commit/6f69f8e67008cff92135065f93dbce392a982759))
* Add release workflow and refactor test/lint workflows ([cae9700](https://github.com/hiro-o918/drydock/commit/cae97007d43696d8a79a939f9ee43a4c14205305))
* Add release workflow and refactor test/lint workflows ([0e95f95](https://github.com/hiro-o918/drydock/commit/0e95f95c9806eea5511bcb7fc4276d516a031b6d))
* fix goreleaser ([597c223](https://github.com/hiro-o918/drydock/commit/597c223f11a7d465d85a8d73036f5d8b21c179dd))
* fix GoReleaser setup and release-please config ([057c70a](https://github.com/hiro-o918/drydock/commit/057c70a5702853c9a907f2c86cd544a8eb170ef8))
* remove test-and-lint job from release workflow ([dde57b9](https://github.com/hiro-o918/drydock/commit/dde57b9db310059a8597df4f3ffd46749200232d))
* set up go releaser ([d71d048](https://github.com/hiro-o918/drydock/commit/d71d048b5c378b1f2953ecbc2c1da066eb04adcc))
* setup goreleaser for project releases ([e1e3540](https://github.com/hiro-o918/drydock/commit/e1e3540ac4f611c6acdb80fd4e786fc5ecb80fef))

## [0.2.0](https://github.com/hiro-o918/drydock/compare/v0.1.0...v0.2.0) (2025-12-07)


### Features

* Add Artifact Registry Analyzer for vulnerability scanning ([c4e678b](https://github.com/hiro-o918/drydock/commit/c4e678bedc68b3352685001ce7ce87b220622a06))
* add cli configurations ([a7f222f](https://github.com/hiro-o918/drydock/commit/a7f222f748537af65303db062181e204b0a1c660))
* add CLI implementation with JSON export ([11d56e4](https://github.com/hiro-o918/drydock/commit/11d56e483143dd398316edc7691317df3e8a4924))
* add generic optional utilities IsZero and ToPtr ([e1f7d78](https://github.com/hiro-o918/drydock/commit/e1f7d78ddfec8f778f6ef9d82b9a62da0503de3e))
* Add ImageResolver for Docker image tag resolution ([4a62d29](https://github.com/hiro-o918/drydock/commit/4a62d292f86c0abc0179c6bfbfc3f6bf2c181dbd))
* Add ImageResolver for Docker image tag resolution ([5bb5a8d](https://github.com/hiro-o918/drydock/commit/5bb5a8dc317e52e2a008fc9f7e4628e7baf10c45))
* add interfaces for drydock ([496a9c6](https://github.com/hiro-o918/drydock/commit/496a9c6079093c10d1ffd6a2cc0d733b274af0ba))
* Add JSON exporter for analysis results ([1e66736](https://github.com/hiro-o918/drydock/commit/1e66736c9f85b04596b23d64f40ad09ecc195749))
* Add JSON repository and location to ImageTarget ([fc66a26](https://github.com/hiro-o918/drydock/commit/fc66a26af040b2e71439d6da26f6115c1ec94487))
* add JSON/YAML serialization tags to export types ([4e07895](https://github.com/hiro-o918/drydock/commit/4e07895520f17a08276d5924aff500baefbb8129))
* add JSON/YAML serialization tags to export types ([b9a0587](https://github.com/hiro-o918/drydock/commit/b9a0587d0ffd2b71583840522095e835c2c1d4a3))
* add linting and formatting configuration ([947340a](https://github.com/hiro-o918/drydock/commit/947340a0361e9e3cbd7fae445965ad260b09b0d7))
* Add Table Exporter for CSV/TSV Formats ([2bad770](https://github.com/hiro-o918/drydock/commit/2bad77020cff6d645f902ed4af1d3821f0481860))
* Add table exporter support and refactor exporter initialization ([c62b31a](https://github.com/hiro-o918/drydock/commit/c62b31aeec9837f5b2092ee4879a648e08d0ea06))
* Add table exporter support for CSV/TSV formats ([ceb57a1](https://github.com/hiro-o918/drydock/commit/ceb57a135b63507f08a79514e91ca1ed437fcc25))
* Enhance Table Exporter with Artifact Details ([c58c6a6](https://github.com/hiro-o918/drydock/commit/c58c6a6db1c7c51bcd0e146083178b8f899a9a07))
* Enhance Table Exporter with Artifact Details ([5a19d46](https://github.com/hiro-o918/drydock/commit/5a19d462b232601aadbd6d4608f7ac0ca951700c))
* implement analyzer ([a1f810e](https://github.com/hiro-o918/drydock/commit/a1f810e46185afeabc1d8067a959d731a6db6323))
* initialize project and stubs ([e9e18f7](https://github.com/hiro-o918/drydock/commit/e9e18f7c959ca5928c6967579b45def55061e140))
* setup ci ([d8c9132](https://github.com/hiro-o918/drydock/commit/d8c9132ade085a999cd00d9cf9b8da66f2d388bf))


### Documentation

* add CLAUDE.md ([2d8e85a](https://github.com/hiro-o918/drydock/commit/2d8e85a514149be4048de0e12dbc6302f2161be5))
* simplify CLAUDE.md ([e7d5e26](https://github.com/hiro-o918/drydock/commit/e7d5e26bbfc06c1d962ac7469b41ec5d922561f2))


### Miscellaneous

* add dependencies for analyzer ([492bfe1](https://github.com/hiro-o918/drydock/commit/492bfe178d17c71872b0662345e7530511986468))
* delete main_test.go ([e180436](https://github.com/hiro-o918/drydock/commit/e1804363d48c486487307d00c902f35ebd17c03b))
* remove unused configs.go file ([de9784f](https://github.com/hiro-o918/drydock/commit/de9784f15dcb40b3cae11147a9d062ae9ffede9d))
* remove unused types ([fc33f4e](https://github.com/hiro-o918/drydock/commit/fc33f4ef577b5831e789c60a1818b3ee7578ee6d))
* run pinact ([abdad16](https://github.com/hiro-o918/drydock/commit/abdad161e40133804b117f9ae98011ed5f1170e5))
* setup GoReleaser workflow for tags ([fed0f19](https://github.com/hiro-o918/drydock/commit/fed0f198da8c69cb14209c0998e25d5a0f6575ed))
* setup logger with zerolog ([361e531](https://github.com/hiro-o918/drydock/commit/361e531f3def2ad2b878d76033de63a199c1020d))
* update .gitignore ([49ffcb7](https://github.com/hiro-o918/drydock/commit/49ffcb7687093d230aa7e401a0c306a07807b2bd))
* update CLAUDE.md ([ac64152](https://github.com/hiro-o918/drydock/commit/ac64152dad991b3cb21e171821e3db9ebb930305))


### Tests

* accept lowercase severity in tests ([65e6574](https://github.com/hiro-o918/drydock/commit/65e657484a061e93b2bcd4d3c4b65a1b028f97b1))


### CI/CD

* add GitHub Actions workflow for testing and linting ([6f69f8e](https://github.com/hiro-o918/drydock/commit/6f69f8e67008cff92135065f93dbce392a982759))
* Add release workflow and refactor test/lint workflows ([cae9700](https://github.com/hiro-o918/drydock/commit/cae97007d43696d8a79a939f9ee43a4c14205305))
* Add release workflow and refactor test/lint workflows ([0e95f95](https://github.com/hiro-o918/drydock/commit/0e95f95c9806eea5511bcb7fc4276d516a031b6d))
* remove test-and-lint job from release workflow ([dde57b9](https://github.com/hiro-o918/drydock/commit/dde57b9db310059a8597df4f3ffd46749200232d))
* set up go releaser ([d71d048](https://github.com/hiro-o918/drydock/commit/d71d048b5c378b1f2953ecbc2c1da066eb04adcc))
* setup goreleaser for project releases ([e1e3540](https://github.com/hiro-o918/drydock/commit/e1e3540ac4f611c6acdb80fd4e786fc5ecb80fef))
