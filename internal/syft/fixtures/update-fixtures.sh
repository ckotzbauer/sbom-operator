#!/bin/bash

syft registry:alpine@sha256:36a03c95c2f0c83775d500101869054b927143a8320728f0e135dc151cb8ae61 -o json > alpine.json
syft registry:alpine@sha256:36a03c95c2f0c83775d500101869054b927143a8320728f0e135dc151cb8ae61 -o cyclonedx > alpine.cyclonedx
syft registry:alpine@sha256:36a03c95c2f0c83775d500101869054b927143a8320728f0e135dc151cb8ae61 -o spdx-json > alpine.spdxjson

syft registry:mysql@sha256:96439dd0d8d085cd90c8001be2c9dde07b8a68b472bd20efcbe3df78cff66492 -o json > mysql.json
syft registry:mysql@sha256:96439dd0d8d085cd90c8001be2c9dde07b8a68b472bd20efcbe3df78cff66492 -o cyclonedx > mysql.cyclonedx
syft registry:mysql@sha256:96439dd0d8d085cd90c8001be2c9dde07b8a68b472bd20efcbe3df78cff66492 -o spdx-json > mysql.spdxjson

syft registry:node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec -o json > node.json
syft registry:node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec -o cyclonedx > node.cyclonedx
syft registry:node@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec -o spdx-json > node.spdxjson
