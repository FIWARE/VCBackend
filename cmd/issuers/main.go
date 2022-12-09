package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/fiware/vcbackend/internal/jwt"
	"github.com/fiware/vcbackend/vault"
	"github.com/hesusruiz/vcutils/yaml"
	zlog "github.com/rs/zerolog/log"
)

type CredentialClaims struct {
	jwt.RegisteredClaims
	Other map[string]any
}

const defaultConfigFile = "configs/server.yaml"

var (
	configFile = flag.String("config", defaultConfigFile, "path to configuration file")
)

func main() {

	// Parse command-line flags
	flag.Parse()

	// Read configuration file
	cfg := readConfiguration(*configFile)

	v, err := vault.New(cfg)
	if err != nil {
		zlog.Panic().Err(err).Send()
	}

	// Parse legal person data
	data, err := yaml.ParseYamlFile("cmd/issuers/sampledata/issuer_data.yaml")
	if err != nil {
		panic(err)
	}
	_, err = json.MarshalIndent(data.Data(), "", "  ")
	if err != nil {
		panic(err)
	}

	// Get the top-level list (the list of legalPersons)
	legalPersons := data.List("")
	if len(legalPersons) == 0 {
		panic("no issuers found in configuration")
	}
	fmt.Println("Issuers", legalPersons)

	// Iterate through the list creating each issuer
	for _, item := range legalPersons {
		fmt.Println("Credential", item)

		cred, _ := item.(map[string]any)

		usr, err := v.CreateLegalPersonWithKey(cred["id"].(string), cred["name"].(string), cred["password"].(string))
		if err != nil {
			zlog.Logger.Error().Err(err).Send()
		}
		fmt.Println(usr)

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
		// fmt.Println(string(cfgDefaults))
		// cfg, err = yaml.ParseYamlBytes(cfgDefaults)
	}
	return cfg
}
