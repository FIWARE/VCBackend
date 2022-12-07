package back

import (
	"github.com/hesusruiz/vcissuer/back/handlers"
	"github.com/hesusruiz/vcissuer/back/operations"
	"github.com/hesusruiz/vcissuer/vault"
	"github.com/hesusruiz/vcutils/yaml"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/storage/memory"
	"go.uber.org/zap"
)

// Server is the struct holding the state of the server
type Server struct {
	*fiber.App
	cfg           *yaml.YAML
	WebAuthn      *handlers.WebAuthnHandler
	Operations    *operations.Manager
	issuerVault   *vault.Vault
	verifierVault *vault.Vault
	walletvault   *vault.Vault
	issuerDID     string
	verifierDID   string
	logger        *zap.SugaredLogger
	storage       *memory.Storage
}

func New(cfg *yaml.YAML) *Server {

	srv := &Server{
		App:           &fiber.App{},
		cfg:           cfg,
		WebAuthn:      &handlers.WebAuthnHandler{},
		Operations:    &operations.Manager{},
		issuerVault:   &vault.Vault{},
		verifierVault: &vault.Vault{},
		walletvault:   &vault.Vault{},
		issuerDID:     "",
		verifierDID:   "",
		logger:        &zap.SugaredLogger{},
		storage:       &memory.Storage{},
	}

	return srv
}
