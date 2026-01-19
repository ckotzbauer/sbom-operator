package cosign

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
)

type Cosign struct {
}

func New() *Cosign {
	return &Cosign{}
}

func (c *Cosign) GetSBOM(img *oci.RegistryImage) (string, error) {
	opt := options.RegistryOptions{}
	atopt := options.AttestationDownloadOptions{
		PredicateType: "cyclonedx",
	}
	builder := new(strings.Builder)
	err := download.AttestationCmd(context.Background(), opt, atopt, img.ImageID, builder)
	if err != nil {
		logrus.Warn("error downloading attestation", err)
		return "", err
	}

	// The actual cyclonedx SBOM within a `application/vnd.dev.sigstore.bundle.v0.3+json` is found in:
	// jq -r .dsseEnvelope.payload | base64 -d | jq .predicate
	// .dsseEnvelope.payload is a in-toto attestation
	var protoBundle protobundle.Bundle
	err = protojson.Unmarshal([]byte(builder.String()), &protoBundle)
	if err != nil {
		logrus.Warn("error parsing attestation", err)
		return "", err
	}

	if protoBundle.MediaType != "application/vnd.dev.sigstore.bundle.v0.3+json" {
		return "", err
	}

	var attestationPayload in_toto.SPDXStatement
	err = json.Unmarshal(protoBundle.GetDsseEnvelope().Payload, &attestationPayload)
	if err != nil {
		logrus.Warn("error parsing attestation", err)
		return "", err
	}

	predicateMap, ok := attestationPayload.Predicate.(map[string]interface{})
	if !ok {
		logrus.Warn("error parsing attestation")
		return "", nil
	}

	predicateBytes, err := json.Marshal(predicateMap)
	if err != nil {
		logrus.Warn("error marshaling predicate", err)
		return "", err
	}

	return string(predicateBytes), nil
}
