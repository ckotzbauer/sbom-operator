## Version 0.10.0-beta.2 (2022-04-27)

### Bug fixes

* [[`35a78e84`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/35a78e84)] - **fix**: use empty array without a secret-name


## Version 0.10.0-beta.1 (2022-04-26)

### Bug fixes

* [[`4e2dee4f`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4e2dee4f)] - **fix**: try to add chmod statement


## Version 0.10.0-beta.0 (2022-04-26)

### Features and improvements

* [[`411a9472`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/411a9472)] - **feat**: add Codenotary CAS support
* [[`91ced753`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/91ced753)] - **feat**: add vcn-metadata-attributes
* [[`4017697d`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4017697d)] - **feat**: allow optional extra-args to VCN
* [[`e0acaea3`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/e0acaea3)] - **feat**: add external job-delegation for vcn

### Bug fixes

* [[`2917d79b`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/2917d79b)] - **fix**: split by regex

### Build and testing

* [[`ffc3025f`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/ffc3025f)] - **build**: fix artifact-path
* [[`c9284846`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/c9284846)] - **build**: add job-image-workflow

### Documentation

* [[`2cf4d68b`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/2cf4d68b)] - **doc**: add amd64 note
* [[`cb42f105`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/cb42f105)] - **doc**: improvements to job-image docs
* [[`a129503c`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/a129503c)] - **doc**: add job-docs

### Dependency updates

* [[`42a92388`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/42a92388)] - **deps**: update kubernetes versions to v0.23.6

### Common changes

* [[`a502a2eb`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/a502a2eb)] - **chore**: split deploy-manifests


## Version 0.9.0 (2022-04-16)

### Build and testing

* [[`0db018a4`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/0db018a4)] - **build**: update to go 1.18.1

### Documentation

* [[`f10035d9`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/f10035d9)] - **doc**: update version-table [skip ci]

### Dependency updates

* [[`4476caf7`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4476caf7)] - **deps**: fix syft-update
* [[`f4ff8e50`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/f4ff8e50)] - **deps**: update module github.com&#x2F;anchore&#x2F;syft to v0.44.1
* [[`609032bd`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/609032bd)] - **deps**: update module github.com&#x2F;spf13&#x2F;viper to v1.11.0
* [[`fb99dbc9`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/fb99dbc9)] - **deps**: update ckotzbauer&#x2F;actions-toolkit action to v0.12.1
* [[`ee2fe84d`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/ee2fe84d)] - **deps**: update alpine digest to 4edbd2b


## Version 0.8.0 (2022-04-08)

### Features and improvements

* [[`e7b902a6`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/e7b902a6)] - **feat**: update to go@1.18.0

### Bug fixes

* [[`0b446e1e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/0b446e1e)] - **fix**: fix parsing of image id&#39;s for container runtimes which include a prefix before the image id
* [[`f495819e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/f495819e)] - **fix**: add namespace close #56

### Build and testing

* [[`fc495e8f`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/fc495e8f)] - **build**: use reusable-workflows [6]
* [[`ccff3ee5`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/ccff3ee5)] - **build**: use reusable-workflows [5]
* [[`90e363d6`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/90e363d6)] - **build**: use reusable-workflows [4]
* [[`2f110068`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/2f110068)] - **build**: use reusable-workflows [3]
* [[`2acc90b8`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/2acc90b8)] - **build**: use reusable-workflows [2]
* [[`b0cba49c`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/b0cba49c)] - **build**: use reusable-workflows [1]
* [[`585cf4ba`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/585cf4ba)] - **test**: update fixtures
* [[`1b46b79e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/1b46b79e)] - **test**: update syft-fixtures

### Documentation

* [[`6e44f2ee`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/6e44f2ee)] - **doc**: update version [skip ci]

### Dependency updates

* [[`1af69827`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/1af69827)] - **deps**: update module github.com&#x2F;anchore&#x2F;syft to v0.43.0
* [[`4bc434a9`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4bc434a9)] - **deps**: update actions&#x2F;setup-node action to v3.1.0
* [[`18984bb1`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/18984bb1)] - **deps**: update ckotzbauer&#x2F;actions-toolkit action to v0.10.1
* [[`bbc680b5`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/bbc680b5)] - **deps**: update alpine digest to f22945d
* [[`3df42d43`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/3df42d43)] - **deps**: update module github.com&#x2F;anchore&#x2F;syft to v0.42.4 (#59)
* [[`53febe7a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/53febe7a)] - **deps**: update alpine digest to ceeae28 (#58)
* [[`4da4adf7`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4da4adf7)] - **deps**: update module github.com&#x2F;docker&#x2F;cli to v20.10.14 (#60)
* [[`c1c1ffda`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/c1c1ffda)] - **deps**: update ckotzbauer&#x2F;actions-toolkit action to v0.10.0 (#61)
* [[`2cd77243`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/2cd77243)] - **deps**: update module github.com&#x2F;onsi&#x2F;gomega to v1.19.0 (#62)
* [[`ec4fa537`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/ec4fa537)] - **deps**: bump pascalgn&#x2F;automerge-action
* [[`8e229eaa`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/8e229eaa)] - **deps**: update ckotzbauer&#x2F;label-command-action action to v2
* [[`08b2d4e8`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/08b2d4e8)] - **deps**: update module github.com&#x2F;anchore&#x2F;syft to v0.42.0
* [[`70834f7b`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/70834f7b)] - **deps**: update alpine digest to d6d0a0e (#52)
* [[`d39e8e1d`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/d39e8e1d)] - **deps**: update kubernetes versions to v0.23.5 (#53)

### Common changes

* [[`2a339356`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/2a339356)] - **chore**: fix rbac for correct install
* [[`7cfcee04`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/7cfcee04)] - **chore**: remove dependabot [skip ci]
* [[`3814029f`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/3814029f)] - **chore**: update community-files [skip ci]


## Version 0.7.0 (2022-03-12)

### Features and improvements

* [[`2fedd5e1`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/2fedd5e1)] - **feat**: delete unused images from Dependency Track

### Bug fixes

* [[`151dde7a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/151dde7a)] - **fix**: rename fixtures
* [[`9fa77304`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/9fa77304)] - **fix**: issue with image cleanup

### Documentation

* [[`4863e43a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4863e43a)] - **doc**: add new version

### Dependency updates

* [[`404a60fe`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/404a60fe)] - **deps**: update to syft@0.41.4
* [[`4b74df4f`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4b74df4f)] - **deps**: update module github.com&#x2F;anchore&#x2F;syft to v0.41.4
* [[`2a52b94a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/2a52b94a)] - **deps**: update module github.com&#x2F;docker&#x2F;cli to v20.10.13 (#48)
* [[`280975c3`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/280975c3)] - **deps**: update ckotzbauer&#x2F;actions-toolkit action to v0.9.0 (#49)
* [[`4fdc6734`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4fdc6734)] - **deps**: update module github.com&#x2F;spf13&#x2F;cobra to v1.4.0 (#51)
* [[`209fa941`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/209fa941)] - **deps**: update lannonbr&#x2F;issue-label-manager-action action to v3.0.1 (#45)
* [[`47ee9f1d`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/47ee9f1d)] - **deps**: update ckotzbauer&#x2F;actions-toolkit action to v0.8.0 (#46)

### Common changes

* [[`9ea6b1ef`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/9ea6b1ef)] - **chore**: pin dockerimage
* [[`5f0574f4`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/5f0574f4)] - **chore**: pin golang version


## Version 0.6.0 (2022-03-05)

### Bug fixes

* [[`a18233fb`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/a18233fb)] - **fix**: fix git-pull error

### Build and testing

* [[`d37c684e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/d37c684e)] - **build**: ignore several cves
* [[`785c5c72`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/785c5c72)] - **build**: use grype for cve-scan

### Documentation

* [[`fe5b3bf4`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/fe5b3bf4)] - **doc**: fix versions [skip ci]
* [[`e78a0b54`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/e78a0b54)] - **doc**: update versions [skip ci]

### Security

* [[`4f7fdeee`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4f7fdeee)] - **security**: update containerd (GHSA-crp2-qrr5-8pq7)

### Dependency updates

* [[`34849c73`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/34849c73)] - **deps**: update to syft@0.40.1
* [[`e8d2f030`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/e8d2f030)] - **deps**: update module github.com&#x2F;anchore&#x2F;syft to v0.40.1
* [[`3e2a6554`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/3e2a6554)] - **deps**: update actions&#x2F;setup-go action to v3
* [[`889b81b2`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/889b81b2)] - **deps**: update actions&#x2F;stale action to v5
* [[`51cf1180`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/51cf1180)] - **deps**: bump azure&#x2F;setup-kubectl from 2.0 to 2.1
* [[`b5a4e8af`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/b5a4e8af)] - **deps**: bump actions&#x2F;checkout from 2 to 3
* [[`0fb9645c`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/0fb9645c)] - **deps**: update ckotzbauer&#x2F;actions-toolkit action to v0.7.0 (#39)
* [[`726ade99`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/726ade99)] - **deps**: update module github.com&#x2F;anchore&#x2F;syft to v0.39.3 (#38)
* [[`f2d51ba7`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/f2d51ba7)] - **deps**: bump actions&#x2F;setup-node from 2.5.1 to 3.0.0


## Version 0.5.0 (2022-02-19)

### Build and testing

* [[`fe403ec2`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/fe403ec2)] - **test**: also disable test-code
* [[`93802fc9`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/93802fc9)] - **test**: add mkdir
* [[`4ea3e2e6`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/4ea3e2e6)] - **test**: disable ACR tests
* [[`f09877de`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/f09877de)] - **test**: updated sbom-fixtures

### Documentation

* [[`005df7da`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/005df7da)] - **doc**: updates

### Dependency updates

* [[`66798cdc`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/66798cdc)] - **deps**: update docker&#x2F;distribution
* [[`0186c68a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/0186c68a)] - **deps**: go mod tidy
* [[`25b3df43`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/25b3df43)] - **deps**: update module github.com&#x2F;anchore&#x2F;syft to v0.38.0
* [[`6463901f`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/6463901f)] - **deps**: go mod tidy
* [[`046ad445`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/046ad445)] - **deps**: update module github.com&#x2F;onsi&#x2F;ginkgo&#x2F;v2 to v2.1.3
* [[`7446b45f`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/7446b45f)] - **deps**: update pascalgn&#x2F;automerge-action commit hash to 0ba0473 (#32)
* [[`f283ebe2`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/f283ebe2)] - **deps**: update pascalgn&#x2F;size-label-action commit hash to a4655c4 (#33)
* [[`73470b9b`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/73470b9b)] - **deps**: update kubernetes versions to v0.23.4 (#34)
* [[`07ae35f4`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/07ae35f4)] - **deps**: update module github.com&#x2F;nscuro&#x2F;dtrack-client to v0.5.0 (#36)
* [[`417fea63`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/417fea63)] - **deps**: update module github.com&#x2F;onsi&#x2F;ginkgo&#x2F;v2 to v2.1.2 (#31)
* [[`030155ff`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/030155ff)] - **deps**: update ckotzbauer&#x2F;actions-toolkit action to v0.6.0 (#28)
* [[`be071dd1`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/be071dd1)] - **deps**: update module github.com&#x2F;nscuro&#x2F;dtrack-client to v0.4.0 (#30)


## Version 0.4.1 (2022-02-04)

### Bug fixes

* [[`6519b666`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/6519b666)] - **fix**: change legacy-support for .dockercfg
* [[`92c41c6e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/92c41c6e)] - **fix**: add support for legacy .dockercfg close #26


## Version 0.4.0 (2022-02-01)

### Features and improvements

* [[`492e99ed`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/492e99ed)] - **feat**: add version, use project auto-creation
* [[`549443d1`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/549443d1)] - **feat**: basic implementation for Dependency Track

### Bug fixes

* [[`67ff2fe7`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/67ff2fe7)] - **fix**: ignore &quot;already up-to-date&quot;
* [[`b384003b`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/b384003b)] - **fix**: avoid concurrent runs
* [[`40024547`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/40024547)] - **fix**: improve target error-handling
* [[`d3a5768a`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/d3a5768a)] - **fix**: also respect dockercfg secret-type close #26
* [[`347b8430`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/347b8430)] - **fix**: add missing rbac-rules close #24

### Build and testing

* [[`e731e895`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/e731e895)] - **build**: also build on PRs

### Documentation

* [[`9d5a1bc1`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/9d5a1bc1)] - **doc**: added dtrack docs
* [[`0e36dbe4`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/0e36dbe4)] - **doc**: improve version docs

### Common changes

* [[`43c84015`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/43c84015)] - **chore**: Fix logging and remove fallback (not needed)
* [[`7fbd4c89`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/7fbd4c89)] - **chore**: Fixed typos Dependenca -&gt; Dependency
* [[`1fa44d04`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/1fa44d04)] - **chore**: Load all projects with paging
* [[`9eff773e`](https://github.com/ckotzbauer&#x2F;sbom-operator/commit/9eff773e)] - **chore**: add target-labels


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


