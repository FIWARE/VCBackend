package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/hesusruiz/vcbackend/internal/jwt"
	"github.com/hesusruiz/vcbackend/vault"
	"github.com/hesusruiz/vcutils/yaml"
	zlog "github.com/rs/zerolog/log"
)

type CredentialClaims struct {
	jwt.RegisteredClaims
	Other map[string]any
}

const defaultConfigFile = "configs/server.yaml"
const defaultCredentialDataFile = "cmd/creds/sampledata/employee_data.yaml"

var (
	configFile = flag.String("config", defaultConfigFile, "path to configuration file")
)

func main() {

	// Parse command-line flags
	flag.Parse()

	// Read configuration file
	cfg := readConfiguration(*configFile)

	// Connect to the Vault
	c, err := vault.New(cfg)
	if err != nil {
		panic(err)
	}

	// Parse credential data
	data, err := yaml.ParseYamlFile(defaultCredentialDataFile)
	if err != nil {
		panic(err)
	}

	// Get the top-level list (the list of credentials)
	creds := data.List("")
	if len(creds) == 0 {
		panic("no credentials found in config")
	}

	// Iterate through the list creating each credential which will use its own template
	for _, item := range creds {

		// Convert to a yaml object
		ic := yaml.New(item)

		// Get the list of roles
		roles := ic.List("claims.roles")
		if len(roles) == 0 {
			zlog.Logger.Error().Msg("no roles found in clams configuration")
			continue
		}

		fmt.Printf("Roles: %v\n", roles)

		// Cast to a map so it can be passed to CreateCredentialFromMap
		cred, _ := item.(map[string]any)
		_, rawCred, err := c.CreateCredentialJWTFromMap(cred)
		if err != nil {
			zlog.Logger.Error().Err(err).Send()
			continue
		}

		// Check that the content is correct by parsing the credential and marshalling it
		b := &CredentialClaims{}
		_, err = jwt.NewParser().ParseUnverified2(string(rawCred), b)
		if err != nil {
			zlog.Logger.Error().Err(err).Send()
			continue
		}
		out, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			zlog.Logger.Error().Err(err).Send()
			continue
		}
		fmt.Println(string(out))

	}

}

// readConfiguration reads a YAML file and creates an easy-to navigate structure
func readConfiguration(configFile string) *yaml.YAML {
	var cfg *yaml.YAML
	var err error

	cfg, err = yaml.ParseYamlFile(configFile)
	if err != nil {
		fmt.Printf("Config file not found, using defaults\n")
		panic(err)
	}
	return cfg
}
