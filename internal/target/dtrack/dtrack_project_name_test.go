package dtrack

import (
	"testing"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kubernetes "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
)

func TestIdentifyProjectNameAndVersion_FallbackHierarchy(t *testing.T) {
	const annotationKey = "sbom.operator/project-name"

	baseContext := func(annotations map[string]string) *target.TargetContext {
		image := &liboci.RegistryImage{
			Image:   "ghcr.io/order-service:1.2.3",
			ImageID: "ghcr.io/order-service@sha256:11115fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
		}
		return &target.TargetContext{
			Image: image,
			Pod: &kubernetes.PodInfo{
				PodName:      "order-service-pod-xyz",
				PodNamespace: "production",
				Annotations:  annotations,
			},
			Containers: []*kubernetes.ContainerInfo{
				{
					Name:  "order-container",
					Image: image,
				}, {
					Name:  "project-name",
					Image: image,
				},
			},
		}
	}

	tests := []struct {
		name                string
		annotationKeyConfig string
		podAnnotations      map[string]string
		templateConfig      string
		useShortName        bool
		clusterID           string
		expectedName        string
		expectedVersion     string
	}{
		{
			name:                "Pod annotation takes precedence over global template and image fallback",
			annotationKeyConfig: annotationKey,
			podAnnotations: map[string]string{
				annotationKey: "custom-annotated-app:9.9.9",
			},
			templateConfig:  "{{.Namespace}}-{{index .ContainerNames 0}}:{{.Tag}}",
			expectedName:    "custom-annotated-app",
			expectedVersion: "9.9.9",
		},
		{
			name:                "Global template is used when no annotation is present on pod",
			annotationKeyConfig: annotationKey,
			podAnnotations:      map[string]string{},
			templateConfig:      "global-cluster-app:3.1.0",
			expectedName:        "global-cluster-app",
			expectedVersion:     "3.1.0",
		},
		{
			name:                "Malformed global template falls back to image repo and version",
			annotationKeyConfig: "",
			podAnnotations:      nil,
			templateConfig:      "{{.InvalidSyntaxUnclosed", // Triggers error in getTemplatedNameAndVersion
			useShortName:        false,
			expectedName:        "ghcr.io/order-service",
			expectedVersion:     "1.2.3",
		},
		{
			name:                "Neither annotation nor template configured -> falls back directly to image",
			annotationKeyConfig: "",
			podAnnotations:      nil,
			templateConfig:      "",
			useShortName:        false,
			expectedName:        "ghcr.io/order-service",
			expectedVersion:     "1.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dtrackTarget := &DependencyTrackTarget{
				projectNameAnnotationKey: tt.annotationKeyConfig,
				templateProjectName:      tt.templateConfig,
				useShortName:             tt.useShortName,
				k8sClusterId:             tt.clusterID,
			}

			ctx := baseContext(tt.podAnnotations)
			actualName, actualVersion := dtrackTarget.identifyProjectNameAndVersion(ctx)

			assert.Equal(t, tt.expectedName, actualName, "Project name mismatch")
			assert.Equal(t, tt.expectedVersion, actualVersion, "Project version mismatch")
			assert.NotEmpty(t, actualName, "Project name must never be empty")
			assert.NotEmpty(t, actualVersion, "Project version must never be empty")
		})
	}
}

func TestGetTemplatedNameAndVersion_TemplateExecution(t *testing.T) {
	dtrackTarget := &DependencyTrackTarget{}

	ctx := &target.TargetContext{
		Image: &liboci.RegistryImage{
			Image:   "ghcr.io/payment-service:2.4.1",
			ImageID: "ghcr.io/payment-service@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
		},
		Pod: &kubernetes.PodInfo{
			PodName:      "payment-pod-1",
			PodNamespace: "finance",
		},
		// Intentionally leave Attestation nil in one case or set it to verify nil-safety
		Attestation: nil,
	}

	containers := []*kubernetes.ContainerInfo{
		{Name: "payment-api"},
		{Name: "istio-proxy"},
	}

	t.Run("Renders ShortName, Tag and index of ContainerNames without nil panic when Attestation is nil", func(t *testing.T) {
		tmpl := "{{index .ContainerNames 0}}-{{.ShortName}}:{{.Tag}}"
		name, version, err := dtrackTarget.getTemplatedNameAndVersion(ctx, tmpl, containers, "", "")

		assert.NoError(t, err)
		assert.Equal(t, "payment-api-payment-service", name)
		assert.Equal(t, "2.4.1", version)
	})

	t.Run("Returns empty strings without error when templateContent is empty", func(t *testing.T) {
		name, version, err := dtrackTarget.getTemplatedNameAndVersion(ctx, "", containers, "", "")

		assert.NoError(t, err)
		assert.Empty(t, name)
		assert.Empty(t, version)
	})

	t.Run("Returns error on unknown template field instead of rendering <no value>", func(t *testing.T) {
		tmpl := "{{.NonExistentField}}:{{.Tag}}"
		name, version, err := dtrackTarget.getTemplatedNameAndVersion(ctx, tmpl, containers, "", "")

		assert.Error(t, err)
		assert.Empty(t, name)
		assert.Empty(t, version)
	})
}

func TestIdentifyProjectNameAndVersion_PredefinedChaining(t *testing.T) {
	const annotationKey = "sbom.operator/project-name"
	const validDigest = "sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec"

	ctx := &target.TargetContext{
		Image: &liboci.RegistryImage{
			Image:   "ghcr.io/my-org/order-service:1.0.0",
			ImageID: "ghcr.io/my-org/order-service@" + validDigest,
		},
		Pod: &kubernetes.PodInfo{
			PodName:      "order-service-pod",
			PodNamespace: "eu-live",
			Annotations: map[string]string{
				// Overrides ONLY the version while keeping the project name from the global template
				annotationKey: "{{.PredefinedName}}:2.5.0-hotfix",
			},
		},
		Containers: []*kubernetes.ContainerInfo{
			{
				Name: "order-container",
				Image: &liboci.RegistryImage{
					Image:   "ghcr.io/my-org/order-service:1.0.0",
					ImageID: "ghcr.io/my-org/order-service@" + validDigest,
				},
			},
		},
	}

	dtrackTarget := &DependencyTrackTarget{
		projectNameAnnotationKey: annotationKey,
		templateProjectName:      "{{.Namespace}}-{{.ShortName}}:{{.PredefinedVersion}}",
		useShortName:             true,
		k8sClusterId:             "prod-cluster",
	}

	name, version := dtrackTarget.identifyProjectNameAndVersion(ctx)

	// Note: docker-parser ShortName() strips registry "ghcr.io/", yielding "my-org/order-service"
	assert.Equal(t, "eu-live-my-org/order-service", name)
	assert.Equal(t, "2.5.0-hotfix", version)
}

func TestIdentifyProjectNameAndVersion_ExtendedEdgeCases(t *testing.T) {
	const annotationKey = "sbom.operator/project-name"
	image := &liboci.RegistryImage{
		Image:   "ghcr.io/my-org/billing/invoice-worker:1.4.2",
		ImageID: "ghcr.io/my-org/billing/invoice-worker@sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec",
	}

	buildContext := func(containerName string, annotations map[string]string) *target.TargetContext {
		return &target.TargetContext{
			Image: image,
			Pod: &kubernetes.PodInfo{
				PodName:      "invoice-worker-7d8f9",
				PodNamespace: "finance-prod",
				Annotations:  annotations,
			},
			Attestation: &oci.AttestationSbom{
				Scope:     oci.ScopeAll,
				MediaType: oci.CycloneDXJSONMediaType,
			},
			Containers: []*kubernetes.ContainerInfo{
				{
					Name:  containerName,
					Image: image,
				},
			},
		}
	}

	tests := []struct {
		name            string
		globalTemplate  string
		useShortName    bool
		clusterID       string
		containerName   string
		podAnnotations  map[string]string
		expectedName    string
		expectedVersion string
	}{
		{
			name:           "1. Full 4-stage chaining (Image -> Global Template -> Pod Annotation -> Container Annotation)",
			globalTemplate: "{{.Namespace}}-{{.PredefinedName}}:{{.PredefinedVersion}}",
			useShortName:   true,
			containerName:  "worker",
			podAnnotations: map[string]string{
				annotationKey:             "{{.PredefinedName}}-pod:{{.PredefinedVersion}}-rc1",
				annotationKey + "/worker": "{{.PredefinedName}}-worker:{{.PredefinedVersion}}-final",
			},
			expectedName:    "finance-prod-my-org/billing/invoice-worker-pod-worker",
			expectedVersion: "1.4.2-rc1-final",
		},
		{
			name:           "2. Partial override: Container annotation overrides ONLY version, keeping global template name",
			globalTemplate: "{{.Namespace}}/{{.ShortName}}:{{.PredefinedVersion}}",
			useShortName:   true,
			containerName:  "worker",
			podAnnotations: map[string]string{
				annotationKey + "/worker": "{{.PredefinedName}}:2026.10.29",
			},
			expectedName:    "finance-prod/my-org/billing/invoice-worker",
			expectedVersion: "2026.10.29",
		},
		{
			name:           "3. Partial override: Pod annotation overrides ONLY name, keeping image version via PredefinedVersion",
			globalTemplate: "",
			useShortName:   false,
			containerName:  "worker",
			podAnnotations: map[string]string{
				annotationKey: "custom-enterprise-billing:{{.PredefinedVersion}}",
			},
			expectedName:    "custom-enterprise-billing",
			expectedVersion: "1.4.2",
		},
		{
			name:           "4. Broken container-specific template falls back gracefully to valid pod-wide annotation",
			globalTemplate: "{{.Namespace}}-{{.ShortName}}:{{.Tag}}",
			useShortName:   true,
			containerName:  "worker",
			podAnnotations: map[string]string{
				annotationKey:             "valid-pod-wide-name:3.0.0",
				annotationKey + "/worker": "{{.UnclosedBrokenTemplate",
			},
			expectedName:    "valid-pod-wide-name",
			expectedVersion: "3.0.0",
		},
		{
			name:           "5. Broken pod-wide annotation and broken global template fall back to image repo and version",
			globalTemplate: "{{.BrokenGlobal",
			useShortName:   true,
			containerName:  "worker",
			podAnnotations: map[string]string{
				annotationKey: "{{.BrokenPodWide",
			},
			expectedName:    "my-org/billing/invoice-worker",
			expectedVersion: "1.4.2",
		},
		{
			name:           "6. Empty container-specific annotation value falls back to pod-wide annotation",
			globalTemplate: "",
			useShortName:   true,
			containerName:  "worker",
			podAnnotations: map[string]string{
				annotationKey:             "pod-wide-app:1.0.0",
				annotationKey + "/worker": "",
			},
			expectedName:    "pod-wide-app",
			expectedVersion: "1.0.0",
		},
		{
			name:           "7. Unrelated annotation sharing prefix without slash is ignored",
			globalTemplate: "{{.Namespace}}-{{.ShortName}}:{{.Tag}}",
			useShortName:   true,
			containerName:  "worker",
			podAnnotations: map[string]string{
				annotationKey + "-other-setting": "wrong-project:9.9.9",
			},
			expectedName:    "finance-prod-my-org/billing/invoice-worker",
			expectedVersion: "1.4.2",
		},
		{
			name:            "8. Template using ContainerNames slice index and SbomScope",
			globalTemplate:  "{{.Namespace}}-{{index .ContainerNames 0}}-{{.SbomScope}}:{{.Tag}}",
			useShortName:    true,
			containerName:   "main-api",
			podAnnotations:  nil,
			expectedName:    "finance-prod-main-api-" + string(oci.ScopeAll),
			expectedVersion: "1.4.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dtrackTarget := &DependencyTrackTarget{
				projectNameAnnotationKey: annotationKey,
				templateProjectName:      tt.globalTemplate,
				useShortName:             tt.useShortName,
				k8sClusterId:             tt.clusterID,
			}

			ctx := buildContext(tt.containerName, tt.podAnnotations)
			name, version := dtrackTarget.identifyProjectNameAndVersion(ctx)

			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedVersion, version)
		})
	}
}

func TestIdentifyParentProjectUuid_ContainerSpecificPrecedence(t *testing.T) {
	const parentKey = "sbom.operator/parent-project"
	const validDigest = "sha256:f527a6118422b888c35162e0a7e2fb2febced4c85a23d96e1342f9edc2789fec"

	podWideUUID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	containerSpecificUUID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	otherContainerUUID := uuid.MustParse("33333333-3333-3333-3333-333333333333")

	g := &DependencyTrackTarget{
		parentProjectAnnotationKey: parentKey,
	}

	ctx := &target.TargetContext{
		Image: &liboci.RegistryImage{
			Image:   "alpine:3.18",
			ImageID: "alpine@" + validDigest,
		},
		Pod: &kubernetes.PodInfo{
			PodName:      "multi-container-pod",
			PodNamespace: "production",
			Annotations: map[string]string{
				parentKey:                    podWideUUID.String(),
				parentKey + "/sidecar-proxy": otherContainerUUID.String(),
				parentKey + "/main-service":  containerSpecificUUID.String(),
			},
		},
		Containers: []*kubernetes.ContainerInfo{
			{Name: "main-service"},
		},
	}

	// Verify deterministic precedence across multiple runs (independent of Go map iteration order)
	for i := 0; i < 20; i++ {
		actualUUID := g.identifyParentProjectUuid(ctx, nil)
		require.NotNil(t, actualUUID)
		assert.Equal(t, containerSpecificUUID, *actualUUID, "Container-specific parent annotation must always take precedence over pod-wide annotation")
	}
}
