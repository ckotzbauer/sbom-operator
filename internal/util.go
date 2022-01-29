package internal

import (
	"fmt"
	"io"
	"math/rand"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// BindFlags binds each cobra flag to its associated viper configuration (environment variable)
func BindFlags(cmd *cobra.Command, args []string) {
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		viper.BindEnv(f.Name, flagToEnvVar(f.Name))
		viper.BindPFlag(f.Name, cmd.PersistentFlags().Lookup(f.Name))

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && viper.IsSet(f.Name) {
			val := viper.Get(f.Name)
			cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
		}
	})
}

// flagToEnvVar converts command flag name to equivalent environment variable name
func flagToEnvVar(flag string) string {
	envVarSuffix := strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))
	return fmt.Sprintf("%s_%s", "SBOM", envVarSuffix)
}

//SetUpLogs set the log output ans the log level
func SetUpLogs(out io.Writer, level string) {
	logrus.SetOutput(out)
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		fmt.Println(err)
	} else {
		logrus.SetLevel(lvl)
	}
}

// Unescape removes backslashes and double-quotes from strings
func Unescape(s string) string {
	s = strings.ReplaceAll(s, "\\", "")
	s = strings.ReplaceAll(s, "\"", "")
	return s
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

//  RandStringBytes generates a random string with the given length
func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
