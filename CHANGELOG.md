## Version 0.3.1 (2022-01-30)

### Bug fixes

* [[`d1b47e06`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/d1b47e06)] - **fix**: remove duplicate path-join fix: #23


## Version 0.3.0 (2022-01-29)

### Features and improvements

* [[`a93d296e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/a93d296e)] - **feat**: add ignore-annotations flag ref: #18
* [[`ed59b5aa`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/ed59b5aa)] - **feat**: track process with annotations
* [[`1c4e3968`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/1c4e3968)] - **feat**: add target-validation handling
* [[`23f5285e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/23f5285e)] - **feat**: some refactoring for multi-targets
* [[`d699f346`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/d699f346)] - **feat**: move git package
* [[`57a69b00`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/57a69b00)] - **feat**: use syft module instead of binary

### Bug fixes

* [[`3aecc2d5`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/3aecc2d5)] - **fix**: make image-path reproducible
* [[`484cc576`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/484cc576)] - **fix**: changed if-condition
* [[`789e7446`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/789e7446)] - **fix**: small bugfixes
* [[`bb68ee18`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/bb68ee18)] - **fix**: use other source-hint
* [[`9fab42bb`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/9fab42bb)] - **fix**: small syft fix

### Cleanup and refactoring

* [[`2e0c59e9`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/2e0c59e9)] - **cleanup**: change env-prefix to SBOM
* [[`188dfd99`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/188dfd99)] - **cleanup**: finalized target-decoupling
* [[`94a7246e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/94a7246e)] - **cleanup**: refactored logic to avoid duplicate scans
* [[`41d33fae`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/41d33fae)] - **cleanup**: small refactoring
* [[`bfe062a2`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/bfe062a2)] - **cleanup**: some refactoring

### Build and testing

* [[`87beaa7e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/87beaa7e)] - **build**: also run unit-tests
* [[`35be5e6c`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/35be5e6c)] - **test**: added syft tests

### Documentation

* [[`70428c73`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/70428c73)] - **doc**: fixes
* [[`9f6c877e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/9f6c877e)] - **doc**: several doc updates
* [[`3c60ff84`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/3c60ff84)] - **doc**: some clarifications
* [[`4b5d9d37`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4b5d9d37)] - **doc**: add parameter

### Dependency updates

* [[`ed732dc9`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/ed732dc9)] - **deps**: go mod tidy for ginkgo
* [[`cbb928fa`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/cbb928fa)] - **deps**: update module github.com&#x2F;onsi&#x2F;ginkgo&#x2F;v2 to v2.1.1
* [[`e6d642f3`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/e6d642f3)] - **deps**: go mod tidy for gomega
* [[`c23777a2`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/c23777a2)] - **deps**: update module github.com&#x2F;onsi&#x2F;gomega to v1.18.1
* [[`9b23b29a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/9b23b29a)] - **deps**: update kubernetes versions to v0.23.3 (#19)
* [[`b91489ad`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/b91489ad)] - **deps**: fix go.sum
* [[`383874c1`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/383874c1)] - **deps**: update module github.com&#x2F;onsi&#x2F;gomega to v1.18.0
* [[`741d0ca9`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/741d0ca9)] - **deps**: fix go.sum
* [[`2a0f035a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/2a0f035a)] - **deps**: update module github.com&#x2F;onsi&#x2F;ginkgo&#x2F;v2 to v2.1.0
* [[`c6702897`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/c6702897)] - **deps**: update ckotzbauer&#x2F;actions-toolkit action to v0.5.0

### Common changes

* [[`a30856d5`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/a30856d5)] - **chore**: go mod tidy
* [[`4996730f`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4996730f)] - **chore**: Create FUNDING.yml


## Version 0.2.0 (2022-01-21)

### Features and improvements

* [[`5caebcc9`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/5caebcc9)] - **feat**: add configurable sbom-format

### Bug fixes

* [[`891dfc7e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/891dfc7e)] - **fix**: remove whole directory on sbom-removal close #8

### Build and testing

* [[`ffea5729`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/ffea5729)] - **build**: try to fix trigger

### Documentation

* [[`f865a13e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/f865a13e)] - **doc**: add helm example values
* [[`8199174a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/8199174a)] - **doc**: several improvements ref: #11

### Security

* [[`b67cc1d0`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/b67cc1d0)] - **security**: update opencontainers&#x2F;image-spec

### Common changes

* [[`870f195b`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/870f195b)] - **chore**: use syft version 0.36.0 on top layer
* [[`96e043cc`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/96e043cc)] - **chore**: change the way of install syft


## Version 0.1.0 (2022-01-20)

### Features and improvements

* [[`c8f9c5e8`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/c8f9c5e8)] - **feat**: rename project
* [[`6ffc128e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/6ffc128e)] - **feat**: added git-path
* [[`a5b6bf5e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/a5b6bf5e)] - **feat**: sbom-cleanup; refactoring and fixing
* [[`a777ccac`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/a777ccac)] - **feat**: more configuration for k8s resources
* [[`295153c7`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/295153c7)] - **feat**: configuration and daemon-service

### Build and testing

* [[`32d2c2fc`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/32d2c2fc)] - **build**: try https:&#x2F;&#x2F;index.docker.io&#x2F;v1&#x2F; server
* [[`068745cb`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/068745cb)] - **build**: use env
* [[`8acf0c86`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/8acf0c86)] - **build**: try using env
* [[`e65faa7f`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/e65faa7f)] - **build**: split steps
* [[`5a75c79d`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/5a75c79d)] - **build**: fix quotes
* [[`ead24faa`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/ead24faa)] - **build**: dry-run
* [[`87d52b47`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/87d52b47)] - **build**: use another action
* [[`3e86bf09`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/3e86bf09)] - **build**: update workflow
* [[`04e560ba`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/04e560ba)] - **build**: update workflow
* [[`383ad576`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/383ad576)] - **build**: update workflow
* [[`6a65f9f7`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/6a65f9f7)] - **build**: update workflow
* [[`79a6b63a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/79a6b63a)] - **build**: add github-workflows
* [[`14b2b912`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/14b2b912)] - **test**: use index.docker.io
* [[`d487a5af`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/d487a5af)] - **test**: split test-registries gh-action
* [[`aaeaf29a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/aaeaf29a)] - **test**: try to fix hub-test
* [[`0eb989b9`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/0eb989b9)] - **test**: write registry-tests

### Documentation

* [[`6261a0c0`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/6261a0c0)] - **doc**: added security
* [[`509bb9ae`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/509bb9ae)] - **docs**: added documents

### Security

* [[`36dbde86`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/36dbde86)] - **security**: update golang.org&#x2F;x&#x2F;crypto

### Dependency updates

* [[`8c58dfef`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/8c58dfef)] - **deps**: updated k8s libraries
* [[`eea2d965`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/eea2d965)] - **deps**: bump azure&#x2F;setup-kubectl from 1 to 2.0

### Common changes

* [[`c9704e7a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/c9704e7a)] - **chore**: add quotes
* [[`5ca4e439`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/5ca4e439)] - **chore**: initial commit


