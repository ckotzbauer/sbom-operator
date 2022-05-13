package registry

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"strings"

	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/config/types"
	"github.com/pkg/errors"
)

// This is ported from https://github.com/docker/cli/blob/v20.10.15/cli/config/configfile/file.go
// The only changes to the original source are the fact, that the "auth" field is not decoded
// when "username" or "password" are not blank to avoid overwrites.

const (
	// This constant is only used for really old config files when the
	// URL wasn't saved as part of the config file and it was just
	// assumed to be this value.
	defaultIndexServer = "https://index.docker.io/v1/"
)

// LegacyLoadFromReader reads the non-nested configuration data given and sets up the
// auth config information with given directory and populates the receiver object
func LegacyLoadFromReader(configData io.Reader, configFile *configfile.ConfigFile) error {
	b, err := ioutil.ReadAll(configData)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(b, &configFile.AuthConfigs); err != nil {
		arr := strings.Split(string(b), "\n")
		if len(arr) < 2 {
			return errors.Errorf("The Auth config file is empty")
		}
		authConfig := types.AuthConfig{}
		origAuth := strings.Split(arr[0], " = ")
		if len(origAuth) != 2 {
			return errors.Errorf("Invalid Auth config file")
		}

		// Only decode the "auth" field when "username" and "password" are blank.
		if len(authConfig.Username) == 0 && len(authConfig.Password) == 0 {
			authConfig.Username, authConfig.Password, err = decodeAuth(origAuth[1])
			if err != nil {
				return err
			}
		}

		authConfig.ServerAddress = defaultIndexServer
		configFile.AuthConfigs[defaultIndexServer] = authConfig
	} else {
		for k, authConfig := range configFile.AuthConfigs {
			// Only decode the "auth" field when "username" and "password" are blank.
			if len(authConfig.Username) == 0 && len(authConfig.Password) == 0 {
				authConfig.Username, authConfig.Password, err = decodeAuth(authConfig.Auth)
				if err != nil {
					return err
				}
			}
			authConfig.Auth = ""
			authConfig.ServerAddress = k
			configFile.AuthConfigs[k] = authConfig
		}
	}
	return nil
}

// decodeAuth decodes a base64 encoded string and returns username and password
func decodeAuth(authStr string) (string, string, error) {
	if authStr == "" {
		return "", "", nil
	}

	decLen := base64.StdEncoding.DecodedLen(len(authStr))
	decoded := make([]byte, decLen)
	authByte := []byte(authStr)
	n, err := base64.StdEncoding.Decode(decoded, authByte)
	if err != nil {
		return "", "", err
	}
	if n > decLen {
		return "", "", errors.Errorf("Something went wrong decoding auth config")
	}
	arr := strings.SplitN(string(decoded), ":", 2)
	if len(arr) != 2 {
		return "", "", errors.Errorf("Invalid auth configuration file")
	}
	password := strings.Trim(arr[1], "\x00")
	return arr[0], password, nil
}
