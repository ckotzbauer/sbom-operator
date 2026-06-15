package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/l3montree-dev/devguard/pkg/devguard"
	parser "github.com/novln/docker-parser"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/l3montree-dev/devguard-operator/kubernetes"
)

type DevGuardTarget struct {
	apiUrl string
	token  string
	tags   []string
	client devguard.HTTPClient
}

type DevGuardRequest struct {
	Verb         string          `json:"verb"`
	ProjectName  string          `json:"projectName"`
	AssetName    string          `json:"assetName"`
	AssetVersion string          `json:"assetVersion"`
	Sbom         json.RawMessage `json:"sbom,omitempty"`
}

type devGuardAssetVersion struct {
	Name string `json:"name"`
}

type devGuardAssetEntry struct {
	Name     string                 `json:"name"`
	Versions []devGuardAssetVersion `json:"assetVersions"`
}

type devGuardAsset struct {
	ProjectName string `json:"projectName"`
	Assets      []struct {
		Name     string   `json:"name"`
		Versions []string `json:"versions"`
	} `json:"assets"`
}

func NewDevGuardTarget(token, apiUrl string, tags []string) *DevGuardTarget {
	client := devguard.NewHTTPClient(token, apiUrl)

	return &DevGuardTarget{
		apiUrl: apiUrl,
		token:  token,
		tags:   tags,
		client: client,
	}
}

func (g *DevGuardTarget) LoadImages() ([]kubernetes.ImageInNamespace, error) {
	req, err := http.NewRequest("GET", g.apiUrl, nil)
	if err != nil {
		return nil, err
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var assets []devGuardAsset
	if err := json.NewDecoder(resp.Body).Decode(&assets); err != nil {
		return nil, err
	}

	result := make([]kubernetes.ImageInNamespace, 0)
	for _, a := range assets {
		for _, asset := range a.Assets {
			for _, version := range asset.Versions {
				fullImage := asset.Name + ":" + version
				result = append(result, kubernetes.ImageInNamespace{
					Namespace: a.ProjectName,
					Image: &libk8s.RegistryImage{
						ImageID: fullImage,
						Image:   fullImage,
					},
				})
			}
		}
	}

	return result, nil
}

func (g *DevGuardTarget) ProcessSbom(ctx *TargetContext) error {

	assetName, version := getRepoWithVersion(ctx.Image)

	if ctx.Sbom == "" {
		slog.Info("Empty SBOM - skip image", "image", ctx.Image.ImageID)
		return nil
	}

	payload := DevGuardRequest{
		Verb:         "update",
		ProjectName:  ctx.Pod.PodNamespace,
		AssetName:    assetName,
		AssetVersion: version,
		Sbom:         json.RawMessage(ctx.Sbom),
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", g.apiUrl, strings.NewReader(string(jsonBody)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	slog.Info("Sending SBOM to DevGuard", "assetName", assetName, "version", version)

	_, err = g.client.Do(req)
	if err != nil {
		slog.Error("Could not upload SBOM", "err", err)
		return err
	}

	slog.Info("Uploaded SBOM to DevGuard", "assetName", assetName, "version", version)
	return nil
}

func (g *DevGuardTarget) Remove(images []kubernetes.ImageInNamespace) error {
	wg := sync.WaitGroup{}

	for _, img := range images {
		wg.Add(1)
		go func(img kubernetes.ImageInNamespace) {
			defer wg.Done()

			name, version := getRepoWithVersion(img.Image)

			payload := DevGuardRequest{
				Verb:         "delete",
				ProjectName:  img.Namespace,
				AssetName:    name,
				AssetVersion: version,
			}

			jsonBody, err := json.Marshal(payload)
			if err != nil {
				slog.Error("could not marshal delete request", "err", err)
				return
			}

			req, err := http.NewRequest("POST", g.apiUrl, strings.NewReader(string(jsonBody)))
			if err != nil {
				slog.Error("could not create delete request", "err", err)
				return
			}

			req.Header.Set("Content-Type", "application/json")

			slog.Info("Deleting asset", "projectName", img.Namespace, "assetName", name, "assetVersion", version)

			_, err = g.client.Do(req)
			if err != nil {
				slog.Error("could not delete asset", "err", err)
				return
			}
		}(img)
	}

	wg.Wait()
	return nil
}

func getRepoWithVersion(image *libk8s.RegistryImage) (string, string) {
	imageRef, err := parser.Parse(image.Image)
	if err != nil {
		slog.Error("Could not parse image", "image", image.Image)
		return "", ""
	}

	projectName := imageRef.Repository()

	if strings.Index(image.Image, "sha256") != 0 {
		imageRef, err = parser.Parse(image.Image)
		if err != nil {
			slog.Error("Could not parse image", "image", image.Image)
			return "", ""
		}
	}

	version := imageRef.Tag()
	return projectName, version
}
