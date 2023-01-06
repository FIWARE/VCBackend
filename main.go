package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/fiware/vcbackend/back/handlers"
	"github.com/fiware/vcbackend/back/operations"
	"github.com/fiware/vcbackend/vault"
	"github.com/hesusruiz/vcutils/yaml"

	"flag"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/storage/memory"
	"github.com/gofiber/template/html"
	"go.uber.org/zap"
)

const defaultConfigFile = "configs/server.yaml"
const defaultTemplateDir = "back/views"
const defaultStaticDir = "back/www"
const defaultStoreDriverName = "sqlite3"
const defaultStoreDataSourceName = "file:issuer.sqlite?mode=rwc&cache=shared&_fk=1"
const defaultPassword = "ThePassword"

const corePrefix = "/core/api/v1"
const issuerPrefix = "/issuer/api/v1"
const verifierPrefix = "/verifier/api/v1"
const walletPrefix = "/wallet/api/v1"

var (
	prod       = flag.Bool("prod", false, "Enable prefork in Production")
	configFile = flag.String("config", LookupEnvOrString("CONFIG_FILE", defaultConfigFile), "path to configuration file")
	password   = flag.String("pass", LookupEnvOrString("PASSWORD", defaultPassword), "admin password for the server")
)

type SSIKitConfig struct {
	coreUrl      string
	signatoryUrl string
	auditorUrl   string
	custodianUrl string
	essifUrl     string
}

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
	ssiKit        *SSIKitConfig
}

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func main() {
	BackendServer()
}

func BackendServer() {
	var err error

	// Create the server instance
	s := &Server{}

	// Read configuration file
	cfg := readConfiguration(*configFile)

	// Create the logger and store in Server so all handlers can use it
	if cfg.String("server.environment") == "production" {
		s.logger = zap.Must(zap.NewProduction()).Sugar()
	} else {
		s.logger = zap.Must(zap.NewDevelopment()).Sugar()
	}
	zap.WithCaller(true)
	defer s.logger.Sync()

	// Parse command-line flags
	flag.Parse()

	// Create the template engine using the templates in the configured directory
	templateDir := cfg.String("server.templateDir", defaultTemplateDir)
	templateEngine := html.New(templateDir, ".html")

	if cfg.String("server.environment") == "development" {
		// Just for development time. Disable when in production
		templateEngine.Reload(true)
	}

	// Define the configuration for Fiber
	fiberCfg := fiber.Config{
		Views:       templateEngine,
		ViewsLayout: "layouts/main",
		Prefork:     *prod,
	}

	// Create a Fiber instance and set it in our Server struct
	s.App = fiber.New(fiberCfg)
	s.cfg = cfg

	// Connect to the different store engines
	s.issuerVault = vault.Must(vault.New(yaml.New(cfg.Map("issuer"))))
	s.verifierVault = vault.Must(vault.New(yaml.New(cfg.Map("verifier"))))
	s.walletvault = vault.Must(vault.New(yaml.New(cfg.Map("wallet"))))

	// Create the issuer and verifier users
	// TODO: the password is only for testing
	s.issuerVault.CreateUserWithKey(cfg.String("issuer.id"), cfg.String("issuer.name"), "legalperson", cfg.String("issuer.password"))
	s.verifierVault.CreateUserWithKey(cfg.String("verifier.id"), cfg.String("verifier.name"), "legalperson", cfg.String("verifier.password"))

	s.ssiKit = fromMap(cfg.Map("ssikit"))

	s.logger.Infof("SSIKit is configured at: %v", s.ssiKit)

	// Create the DIDs for the issuer and verifier
	s.issuerDID, err = operations.SSIKitCreateDID(s.ssiKit.custodianUrl, s.issuerVault, cfg.String("issuer.id"))
	if err != nil {
		panic(err)
	}
	s.logger.Infow("IssuerDID created", "did", s.issuerDID)

	s.verifierDID, err = operations.SSIKitCreateDID(s.ssiKit.custodianUrl, s.verifierVault, cfg.String("verifier.id"))
	if err != nil {
		panic(err)
	}
	s.logger.Infow("VerifierDID created", "did", s.verifierDID)

	// Backend Operations, with its DB connection configuration
	s.Operations = operations.NewManager(cfg)

	// Recover panics from the HTTP handlers so the server continues running
	s.Use(recover.New(recover.Config{EnableStackTrace: true}))

	// CORS
	s.Use(cors.New())

	// Create a storage entry for logon expiration
	s.storage = memory.New()
	defer s.storage.Close()

	// WebAuthn
	// app.WebAuthn = handlers.NewWebAuthnHandler(app.App, app.Operations, cfg)

	// ##########################
	// Application Home pages
	s.Get("/", s.HandleHome)
	s.Get("/issuer", s.HandleIssuerHome)
	s.Get("/verifier", s.HandleVerifierHome)

	// Info base path
	s.Get("/info", s.GetBackendInfo)

	// WARNING! This is just for development. Disable this in production by using the config file setting
	if cfg.String("server.environment") == "development" {
		s.Get("/stop", s.HandleStop)
	}

	// Setup the Issuer, Wallet and Verifier routes
	setupIssuer(s)
	setupEnterpriseWallet(s)
	setupVerifier(s)

	setupCoreRoutes(s)

	// Setup static files
	s.Static("/static", cfg.String("server.staticDir", defaultStaticDir))

	// Start the server
	log.Fatal(s.Listen(cfg.String("server.listenAddress")))

}

func setupCoreRoutes(s *Server) {
	// ########################################
	// Core routes
	coreRoutes := s.Group(corePrefix)

	// Create DID
	coreRoutes.Get("/createdid", s.CoreAPICreateDID)
	// List Templates
	coreRoutes.Get("/listcredentialtemplates", s.CoreAPIListCredentialTemplates)
	// Get one template
	coreRoutes.Get("/getcredentialtemplate/:id", s.CoreAPIGetCredentialTemplate)

}

func fromMap(configMap map[string]any) (skc *SSIKitConfig) {
	coreUrl, ok := configMap["coreURL"]
	if !ok {
		panic(errors.New("no_core_url"))
	}
	custodianUrl, ok := configMap["custodianURL"]
	if !ok {
		panic(errors.New("no_custodian_url"))
	}
	signatoryUrl, ok := configMap["signatoryURL"]
	if !ok {
		panic(errors.New("no_signatory_url"))
	}
	essifUrl, ok := configMap["essifURL"]
	if !ok {
		panic(errors.New("no_essif_url"))
	}
	auditorUrl, ok := configMap["auditorURL"]
	if !ok {
		panic(errors.New("no_auditor_url"))
	}
	return &SSIKitConfig{coreUrl: coreUrl.(string), signatoryUrl: signatoryUrl.(string), auditorUrl: auditorUrl.(string), essifUrl: essifUrl.(string), custodianUrl: custodianUrl.(string)}
}

type backendInfo struct {
	IssuerDID   string `json:"issuerDid"`
	VerifierDID string `json:"verifierDid"`
}

func (s *Server) GetBackendInfo(c *fiber.Ctx) error {
	info := backendInfo{IssuerDID: s.issuerDID, VerifierDID: s.verifierDID}

	return c.JSON(info)
}

func (s *Server) HandleHome(c *fiber.Ctx) error {

	// Render index
	return c.Render("index", "")
}

func (s *Server) HandleStop(c *fiber.Ctx) error {
	os.Exit(0)
	return nil
}

func (s *Server) HandleIssuerHome(c *fiber.Ctx) error {

	// Get the list of credentials
	credsSummary, err := s.Operations.GetAllCredentials()
	if err != nil {
		return err
	}

	// Render template
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"prefix":         issuerPrefix,
		"credlist":       credsSummary,
	}
	return c.Render("issuer_home", m)
}

func (s *Server) HandleVerifierHome(c *fiber.Ctx) error {

	// Get the list of credentials
	credsSummary, err := s.Operations.GetAllCredentials()
	if err != nil {
		return err
	}

	// Render template
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"prefix":         verifierPrefix,
		"credlist":       credsSummary,
	}
	return c.Render("verifier_home", m)
}

func generateNonce() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	nonce := base64.RawURLEncoding.EncodeToString(b)
	return nonce
}

var sameDevice = false

func (s *Server) VerifierAPIJWKS(c *fiber.Ctx) error {

	// Get public keys from Verifier
	pubkeys, err := s.verifierVault.PublicKeysForUser(s.cfg.String("verifier.id"))
	if err != nil {
		return err
	}

	return c.JSON(pubkeys)

}

func (s *Server) HandleAuthenticationRequest(c *fiber.Ctx) error {

	// Get the list of credentials
	credsSummary, err := s.Operations.GetAllCredentials()
	if err != nil {
		return err
	}

	// Render template
	m := fiber.Map{
		"prefix":   verifierPrefix,
		"credlist": credsSummary,
	}
	return c.Render("wallet_selectcredential", m)
}

// readConfiguration reads a YAML file and creates an easy-to navigate structure
func readConfiguration(configFile string) *yaml.YAML {
	var cfg *yaml.YAML
	var err error

	cfg, err = yaml.ParseYamlFile(configFile)
	if err != nil {
		fmt.Printf("Config file not found, exiting\n")
		panic(err)
	}
	return cfg
}

// DID handling
func (srv *Server) CoreAPICreateDID(c *fiber.Ctx) error {

	// body := c.Body()

	// Call the SSI Kit
	agent := fiber.Post(srv.ssiKit.custodianUrl + "/did/create")
	bodyRequest := fiber.Map{
		"method": "key",
	}
	agent.JSON(bodyRequest)
	agent.ContentType("application/json")
	agent.Set("accept", "application/json")
	_, returnBody, errors := agent.Bytes()
	if len(errors) > 0 {
		srv.logger.Errorw("error calling SSI Kit", zap.Errors("errors", errors))
		return fmt.Errorf("error calling SSI Kit: %v", errors[0])
	}

	c.Set("Content-Type", "application/json")
	return c.Send(returnBody)

}

func (srv *Server) CoreAPIListCredentialTemplates(c *fiber.Ctx) error {

	// Call the SSI Kit
	agent := fiber.Get(srv.ssiKit.signatoryUrl + "/v1/templates")
	agent.Set("accept", "application/json")
	_, returnBody, errors := agent.Bytes()
	if len(errors) > 0 {
		srv.logger.Errorw("error calling SSI Kit", zap.Errors("errors", errors))
		return fmt.Errorf("error calling SSI Kit: %v", errors[0])
	}

	c.Set("Content-Type", "application/json")
	return c.Send(returnBody)

}

func (srv *Server) CoreAPIGetCredentialTemplate(c *fiber.Ctx) error {

	id := c.Params("id")
	if len(id) == 0 {
		return fmt.Errorf("no template id specified")
	}

	// Call the SSI Kit
	agent := fiber.Get(srv.ssiKit.signatoryUrl + "/v1/templates/" + id)
	agent.Set("accept", "application/json")
	_, returnBody, errors := agent.Bytes()
	if len(errors) > 0 {
		srv.logger.Errorw("error calling SSI Kit", zap.Errors("errors", errors))
		return fmt.Errorf("error calling SSI Kit: %v", errors[0])
	}

	c.Set("Content-Type", "application/json")
	return c.Send(returnBody)

}

func prettyFormatJSON(in []byte) string {
	decoded := &fiber.Map{}
	json.Unmarshal(in, decoded)
	out, _ := json.MarshalIndent(decoded, "", "  ")
	return string(out)
}
