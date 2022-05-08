package registry

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/config/types"
	"github.com/stretchr/testify/assert"
)

func TestOldJSONReaderNoFile(t *testing.T) {
	js := `{"https://index.docker.io/v1/":{"auth":"am9lam9lOmhlbGxv","email":"user@example.com"}}`
	configFile := configfile.ConfigFile{
		AuthConfigs: make(map[string]types.AuthConfig),
	}

	err := LegacyLoadFromReader(strings.NewReader(js), &configFile)
	assert.Nil(t, err)

	ac := configFile.AuthConfigs["https://index.docker.io/v1/"]
	assert.Equal(t, ac.Username, "joejoe")
	assert.Equal(t, ac.Password, "hello")
}

func TestLegacyJSONSaveWithNoFile(t *testing.T) {
	js := `{"https://index.docker.io/v1/":{"auth":"am9lam9lOmhlbGxv","email":"user@example.com"}}`
	configFile := configfile.ConfigFile{
		AuthConfigs: make(map[string]types.AuthConfig),
	}

	err := LegacyLoadFromReader(strings.NewReader(js), &configFile)
	assert.Nil(t, err)
	err = configFile.Save()
	assert.ErrorContains(t, err, "with empty filename")

	tmpHome, err := ioutil.TempDir("", "config-test")
	assert.Nil(t, err)
	defer os.RemoveAll(tmpHome)

	fn := filepath.Join(tmpHome, config.ConfigFileName)
	f, _ := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer f.Close()

	assert.Nil(t, configFile.SaveToWriter(f))
	buf, err := ioutil.ReadFile(filepath.Join(tmpHome, config.ConfigFileName))
	assert.Nil(t, err)

	expConfStr := `{
	"auths": {
		"https://index.docker.io/v1/": {
			"auth": "am9lam9lOmhlbGxv",
			"email": "user@example.com"
		}
	}
}`

	if string(buf) != expConfStr {
		t.Fatalf("Should have save in new form: \n%s\n not \n%s", string(buf), expConfStr)
	}
}
