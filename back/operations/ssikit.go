package operations

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/hesusruiz/vcbackend/vault"
	"github.com/hesusruiz/vcutils/yaml"
	"go.uber.org/zap"
)

var logger = zap.Must(zap.NewDevelopment())

func SSIKitCreateDID(config *yaml.YAML, v *vault.Vault, userid string) (string, error) {
	defer logger.Sync()

	custodianUrl := config.String("custodianURL")

	// Create a new DID only if it does not exist
	did, _ := v.GetDIDForUser(userid)
	if len(did) > 0 {
		return did, nil
	}

	// Call the SSI Kit
	agent := fiber.Post(custodianUrl + "/did/create")
	bodyRequest := fiber.Map{
		"method": "key",
	}
	agent.JSON(bodyRequest)
	agent.ContentType("application/json")
	agent.Set("accept", "application/json")
	_, returnBody, errors := agent.Bytes()
	if len(errors) > 0 {
		err := fmt.Errorf("error calling SSI Kit: %v", errors[0])
		logger.Error("error calling SSI Kit", zap.Error(err))
		return "", err
	}

	did = string(returnBody)
	// Store the new DID for the specified user
	v.SetDIDForUser(userid, did)

	return did, nil
}
