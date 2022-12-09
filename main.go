package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fiware/vcbackend/back/handlers"
	"github.com/fiware/vcbackend/back/operations"
	"github.com/fiware/vcbackend/vault"
	"github.com/hesusruiz/vcutils/yaml"

	"flag"
	"log"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/valyala/fasttemplate"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/utils"
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
	port       = flag.String("port", ":8000", "Port to listen on")
	prod       = flag.Bool("prod", false, "Enable prefork in Production")
	configFile = flag.String("config", defaultConfigFile, "path to configuration file")
	password   = flag.String("pass", defaultPassword, "admin password for the server")
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

	// Create the DIDs for the issuer and verifier
	s.issuerDID, err = operations.SSIKitCreateDID(s.issuerVault, cfg.String("issuer.id"))
	if err != nil {
		panic(err)
	}
	s.logger.Infow("IssuerDID created", "did", s.issuerDID)

	s.verifierDID, err = operations.SSIKitCreateDID(s.verifierVault, cfg.String("verifier.id"))
	if err != nil {
		panic(err)
	}
	s.logger.Infow("VerifierDID created", "did", s.verifierDID)

	// Backend Operations, with its DB connection configuration
	s.Operations = operations.NewManager(cfg)

	// Recover panics from the HTTP handlers so the server continues running
	s.Use(recover.New(recover.Config{EnableStackTrace: true}))

	s.Use(logger.New(logger.Config{
		// TimeFormat: "02-Jan-1985",
		TimeZone: "Europe/Brussels",
	}))

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

	// WARNING! This is just for development. Disable this in production by using the config file setting
	if cfg.String("server.environment") == "development" {
		s.Get("/stop", s.HandleStop)
	}

	// Setup the Issuer, Wallet and Verifier routes
	setupIssuer(s)
	setupEnterpriseWallet(s)
	setupVerifier(s)

	// Setup static files
	s.Static("/static", cfg.String("server.staticDir", defaultStaticDir))

	// Start the server
	log.Fatal(s.Listen(cfg.String("server.listenAddress")))

}

// setupIssuer creates and setups the Issuer routes
func setupIssuer(s *Server) {

	// // Connect to the Issuer store engine
	// s.issuerVault = vault.Must(vault.New(yaml.New(s.cfg.Map("issuer"))))

	// CSRF for protecting the forms
	csrfHandler := csrf.New(csrf.Config{
		KeyLookup:      "form:_csrf",
		ContextKey:     "csrftoken",
		CookieName:     "csrf_",
		CookieSameSite: "Strict",
		Expiration:     1 * time.Hour,
		KeyGenerator:   utils.UUID,
	})

	// Define the prefix for Issuer routes
	issuerRoutes := s.Group(issuerPrefix)

	// Forms for new credential
	issuerRoutes.Get("/newcredential", csrfHandler, s.IssuerPageNewCredentialFormDisplay)
	issuerRoutes.Post("/newcredential", csrfHandler, s.IssuerPageNewCredentialFormPost)

	// Display details of a credential
	issuerRoutes.Get("/creddetails/:id", s.IssuerPageCredentialDetails)

	// Display a QR with a URL for retrieving the credential from the server
	issuerRoutes.Get("/displayqrurl/:id", s.IssuerPageDisplayQRURL)

	// Get a list of all credentials
	issuerRoutes.Get("/allcredentials", s.IssuerAPIAllCredentials)

	// Get a credential given its ID
	issuerRoutes.Get("/credential/:id", s.IssuerAPICredential)

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

// setupVerifier creates and setups the Issuer routes
func setupVerifier(s *Server) {

	// Define the prefix for Verifier routes
	verifierRoutes := s.Group(verifierPrefix)

	// Routes consist of a set of pages rendering HTML using templates and a set of APIs

	// Pages

	// Display a QR code for mobile wallet or a link for enterprise wallet
	verifierRoutes.Get("/displayqr", s.VerifierPageDisplayQRSIOP)

	// Error page when login session has expired without the user sending the credential
	verifierRoutes.Get("/loginexpired", s.VerifierPageLoginExpired)

	// For same-device logins (e.g., with the enterprise wallet)
	verifierRoutes.Get("/startsiopsamedevice", s.VerifierPageStartSIOPSameDevice)

	// Page displaying the received credential, after successful login
	verifierRoutes.Get("/receivecredential/:state", s.VerifierPageReceiveCredential)

	// Allow simulation of accessing protected resources, after successful login
	verifierRoutes.Get("/accessprotectedservice", s.VerifierPageAccessProtectedService)

	// APIs

	// Used by the login page from the browser, to check successful login or expiration
	verifierRoutes.Get("/poll/:state", s.VerifierAPIPoll)

	// Start the SIOP flows
	verifierRoutes.Get("/startsiop", s.VerifierAPIStartSIOP)
	verifierRoutes.Get("/authenticationrequest", s.VerifierAPIStartSIOP)

	// Used by the wallet (both enterprise and mobile) to send the VC/VP as Authentication Response
	verifierRoutes.Post("/authenticationresponse", s.VerifierAPIAuthenticationResponse)

}

// setupEnterpriseWallet sreates and setups the Enterprise Wallet routes
func setupEnterpriseWallet(s *Server) {

	// Define the prefix for Wallet routes
	walletRoutes := s.Group(walletPrefix)

	// Page to display the available credentials (from the Issuer)
	walletRoutes.Get("/selectcredential", s.WalletPageSelectCredential)

	// To send a credential to the Verifier
	walletRoutes.Get("/sendcredential", s.WalletPageSendCredential)

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

func (s *Server) IssuerPageDisplayQRURL(c *fiber.Ctx) error {

	// Get the credential ID from the path parameter
	id := c.Params("id")

	// Generate the state that will be used for checking expiration
	state := generateNonce()

	// Create an entry in storage that will expire in 2 minutes
	// The entry is identified by the nonce
	// s.storage.Set(state, []byte("pending"), 2*time.Minute)
	s.storage.Set(state, []byte("pending"), 40*time.Second)

	// QR code for cross-device SIOP
	template := "{{protocol}}://{{hostname}}{{prefix}}/credential/{{id}}?state={{state}}"
	t := fasttemplate.New(template, "{{", "}}")
	str := t.ExecuteString(map[string]interface{}{
		"protocol": c.Protocol(),
		"hostname": c.Hostname(),
		"prefix":   issuerPrefix,
		"id":       id,
		"state":    state,
	})

	// Create the QR
	png, err := qrcode.Encode(str, qrcode.Medium, 256)
	if err != nil {
		return err
	}

	// Convert to a dataURL
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	// Render index
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"qrcode":         base64Img,
		"state":          state,
	}
	return c.Render("issuer_present_qr", m)
}

func generateNonce() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	nonce := base64.RawURLEncoding.EncodeToString(b)
	return nonce
}

var sameDevice = false

func (s *Server) VerifierPageDisplayQR(c *fiber.Ctx) error {

	if sameDevice {
		return s.VerifierPageStartSIOPSameDevice(c)
	}

	// Generate the state that will be used for checking expiration
	state := generateNonce()

	// Create an entry in storage that will expire in 2 minutes
	// The entry is identified by the nonce
	// s.storage.Set(state, []byte("pending"), 2*time.Minute)
	s.storage.Set(state, []byte("pending"), 40*time.Second)

	// QR code for cross-device SIOP
	template := "{{protocol}}://{{hostname}}{{prefix}}/startsiop?state={{state}}"
	qrCode1, err := qrCode(template, c.Protocol(), c.Hostname(), verifierPrefix, state)
	if err != nil {
		return err
	}

	// Render index
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"qrcode":         qrCode1,
		"prefix":         verifierPrefix,
		"state":          state,
	}
	return c.Render("verifier_present_qr", m)
}

func qrCode(template, protocol, hostname, prefix, state string) (string, error) {

	// Construct the URL to be included in the QR
	t := fasttemplate.New(template, "{{", "}}")
	str := t.ExecuteString(map[string]interface{}{
		"protocol": protocol,
		"hostname": hostname,
		"prefix":   prefix,
		"state":    state,
	})

	// Create the QR
	png, err := qrcode.Encode(str, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}

	// Convert to a dataURL
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	return base64Img, nil

}

func createAuthenticationRequest(verifierDID string, redirect_uri string, state string) string {

	// This specifies the type of credential that the Verifier will accept
	// TODO: In this use case it is hardcoded, which is enough if the Verifier is simple and uses
	// only one type of credential for authentication its users.
	const scope = "dsba.credentials.presentation.PacketDeliveryService"

	// The response type should be 'vp_token'
	const response_type = "vp_token"

	// Response mode should be 'post'
	const response_mode = "post"

	// We use a template to generate the final string
	template := "openid://?scope={{scope}}" +
		"&response_type={{response_type}}" +
		"&response_mode={{response_mode}}" +
		"&client_id={{client_id}}" +
		"&redirect_uri={{redirect_uri}}" +
		"&state={{state}}" +
		"&nonce={{nonce}}"

	t := fasttemplate.New(template, "{{", "}}")
	authRequest := t.ExecuteString(map[string]interface{}{
		"scope":         scope,
		"response_type": response_type,
		"response_mode": response_mode,
		"client_id":     verifierDID,
		"redirect_uri":  redirect_uri,
		"state":         state,
		"nonce":         generateNonce(),
	})

	return authRequest

}

func (s *Server) VerifierPageDisplayQRSIOP(c *fiber.Ctx) error {

	// Generate the state that will be used for checking expiration and also successful logon
	state := generateNonce()

	// Create an entry in storage that will expire.
	// The entry is identified by the nonce
	s.storage.Set(state, []byte("pending"), 200*time.Second)

	// This is the endpoint inside the QR that the wallet will use to send the VC/VP
	redirect_uri := c.Protocol() + "://" + c.Hostname() + verifierPrefix + "/authenticationresponse"

	// Create the Authentication Request
	authRequest := createAuthenticationRequest(s.verifierDID, redirect_uri, state)
	s.logger.Info("AuthRequest", authRequest)

	// Create the QR code for cross-device SIOP
	png, err := qrcode.Encode(authRequest, qrcode.Medium, 256)
	if err != nil {
		return err
	}

	// Convert the image data to a dataURL
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	// Render the page
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"qrcode":         base64Img,
		"prefix":         verifierPrefix,
		"state":          state,
	}
	return c.Render("verifier_present_qr", m)
}

func (s *Server) WalletAPICreatePresentation(creds []string, holder string) (string, error) {

	type inputCreatePresentation struct {
		Vcs       []string `json:"vcs,omitempty"`
		HolderDid string   `json:"holderDid,omitempty"`
	}

	postBody := inputCreatePresentation{
		Vcs:       creds,
		HolderDid: holder,
	}

	custodianURL := s.cfg.String("ssikit.custodianURL")

	// Call the SSI Kit
	agent := fiber.Post(custodianURL + "/credentials/present")
	agent.Set("accept", "application/json")
	agent.JSON(postBody)
	_, returnBody, errors := agent.Bytes()
	if len(errors) > 0 {
		s.logger.Errorw("error calling SSI Kit", zap.Errors("errors", errors))
		return "", fmt.Errorf("error calling SSI Kit: %v", errors[0])
	}

	fmt.Println("presentation", string(returnBody))

	return string(returnBody), nil

}

// VerifierAPIAuthenticationResponseVP receives a VP, extracts the VC and display a page
func (s *Server) VerifierAPIAuthenticationResponseVP(c *fiber.Ctx) error {

	// Get the state, which indicates the login session to which this request belongs
	state := c.Query("state")

	// We should receive the Verifiable Presentation in the body as JSON
	body := c.Body()
	fmt.Println(string(body))

	// Decode into a map
	vp, err := yaml.ParseJson(string(body))
	if err != nil {
		s.logger.Errorw("invalid vp received", zap.Error(err))
		return err
	}

	credential := vp.String("credential")
	// Validate the credential

	// Set the credential in storage, and wait for the polling from client
	s.storage.Set(state, []byte(credential), 10*time.Second)

	return c.SendString("ok")
}

func (s *Server) VerifierAPIPoll(c *fiber.Ctx) error {

	// get the state
	state := c.Params("state")

	// Check if session still pending
	status, _ := s.storage.Get(state)
	if len(status) == 0 {
		return c.SendString("expired")
	} else {
		return c.SendString(string(status))
	}

}

func (s *Server) VerifierPageLoginExpired(c *fiber.Ctx) error {
	m := fiber.Map{
		"prefix": verifierPrefix,
	}
	return c.Render("verifier_loginexpired", m)
}

func (s *Server) VerifierPageStartSIOPSameDevice(c *fiber.Ctx) error {

	state := c.Query("state")

	const scope = "dsba.credentials.presentation.PacketDeliveryService"
	const response_type = "vp_token"
	redirect_uri := c.Protocol() + "://" + c.Hostname() + verifierPrefix + "/authenticationresponse"

	// template := "https://hesusruiz.github.io/faster/?scope={{scope}}" +
	// 	"&response_type={{response_type}}" +
	// 	"&response_mode=post" +
	// 	"&client_id={{client_id}}" +
	// 	"&redirect_uri={{redirect_uri}}" +
	// 	"&state={{state}}" +
	// 	"&nonce={{nonce}}"

	walletUri := c.Protocol() + "://" + c.Hostname() + walletPrefix + "/selectcredential"
	template := walletUri + "/?scope={{scope}}" +
		"&response_type={{response_type}}" +
		"&response_mode=post" +
		"&client_id={{client_id}}" +
		"&redirect_uri={{redirect_uri}}" +
		"&state={{state}}" +
		"&nonce={{nonce}}"

	t := fasttemplate.New(template, "{{", "}}")
	str := t.ExecuteString(map[string]interface{}{
		"scope":         scope,
		"response_type": response_type,
		"client_id":     s.verifierDID,
		"redirect_uri":  redirect_uri,
		"state":         state,
		"nonce":         generateNonce(),
	})
	fmt.Println(str)

	return c.Redirect(str)
}

func (s *Server) VerifierAPIStartSIOP(c *fiber.Ctx) error {

	// Get the state
	state := c.Query("state")

	const scope = "dsba.credentials.presentation.PacketDeliveryService"
	const response_type = "vp_token"
	redirect_uri := c.Protocol() + "://" + c.Hostname() + verifierPrefix + "/authenticationresponse"

	template := "openid://?scope={{scope}}" +
		"&response_type={{response_type}}" +
		"&response_mode=post" +
		"&client_id={{client_id}}" +
		"&redirect_uri={{redirect_uri}}" +
		"&state={{state}}" +
		"&nonce={{nonce}}"

	t := fasttemplate.New(template, "{{", "}}")
	str := t.ExecuteString(map[string]interface{}{
		"scope":         scope,
		"response_type": response_type,
		"client_id":     s.verifierDID,
		"redirect_uri":  redirect_uri,
		"state":         state,
		"nonce":         generateNonce(),
	})
	fmt.Println(str)

	return c.SendString(str)
}

func (s *Server) VerifierAPIAuthenticationResponse(c *fiber.Ctx) error {

	// Get the state
	state := c.Query("state")

	// We should receive the credential in the body as JSON
	body := c.Body()
	fmt.Println(string(body))

	// Decode into a map
	cred, err := yaml.ParseJson(string(body))
	if err != nil {
		s.logger.Errorw("invalid credential received", zap.Error(err))
		return err
	}

	credential := cred.String("credential")
	// Validate the credential

	// Set the credential in storage, and wait for the polling from client
	s.storage.Set(state, []byte(credential), 10*time.Second)

	return c.SendString("ok")
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

func (s *Server) IssuerAPIAllCredentials(c *fiber.Ctx) error {

	// Get the list of credentials
	credsSummary, err := s.Operations.GetAllCredentials()
	if err != nil {
		return err
	}

	return c.JSON(credsSummary)
}

func (s *Server) IssuerAPICredential(c *fiber.Ctx) error {

	// Get the ID of the credential
	credID := c.Params("id")

	// Get the raw credential from the Vault
	rawCred, err := s.issuerVault.Client.Credential.Get(context.Background(), credID)
	if err != nil {
		return err
	}

	return c.SendString(string(rawCred.Raw))
}

func (s *Server) WalletPageSelectCredential(c *fiber.Ctx) error {

	type authRequest struct {
		Scope         string `query:"scope"`
		Response_mode string `query:"response_mode"`
		Response_type string `query:"response_type"`
		Client_id     string `query:"client_id"`
		Redirect_uri  string `query:"redirect_uri"`
		State         string `query:"state"`
		Nonce         string `query:"nonce"`
	}

	ar := new(authRequest)
	if err := c.QueryParser(ar); err != nil {
		return err
	}

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
		"prefix":         walletPrefix,
		"authRequest":    ar,
		"credlist":       credsSummary,
	}
	return c.Render("wallet_selectcredential", m)
}

func (s *Server) WalletPageSendCredential(c *fiber.Ctx) error {

	// Get the ID of the credential
	credID := c.Query("id")
	s.logger.Info("credID", credID)

	// Get the url where we have to send the credential
	redirect_uri := c.Query("redirect_uri")
	s.logger.Info("redirect_uri", redirect_uri)

	// Get the state nonce
	state := c.Query("state")
	s.logger.Info("state", state)

	// Get the raw credential from the Vault
	// TODO: change to the vault of the wallet without relying on the issuer
	rawCred, err := s.issuerVault.Client.Credential.Get(context.Background(), credID)
	if err != nil {
		return err
	}

	// Prepare to POST the credential to the url, passing the state
	agent := fiber.Post(redirect_uri)
	agent.QueryString("state=" + state)

	// Set the credential in the body of the request
	bodyRequest := fiber.Map{
		"credential": string(rawCred.Raw),
	}
	agent.JSON(bodyRequest)

	// Set content type, both for request and accepted reply
	agent.ContentType("application/json")
	agent.Set("accept", "application/json")

	// Send the request.
	// We are interested only in the success of the request.
	code, _, errors := agent.Bytes()
	if len(errors) > 0 {
		s.logger.Errorw("error sending credential", zap.Errors("errors", errors))
		return fmt.Errorf("error sending credential: %v", errors[0])
	}

	fmt.Println("code:", code)

	// Tell the user that it was OK
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"prefix":         verifierPrefix,
		"error":          "",
	}
	if code < 200 || code > 299 {
		m["error"] = fmt.Sprintf("Error calling server: %v", code)
	}
	return c.Render("wallet_credentialsent", m)
}

func (s *Server) VerifierPageReceiveCredential(c *fiber.Ctx) error {

	// Get the state as a path parameter
	state := c.Params("state")

	// get the credential from the storage
	rawCred, _ := s.storage.Get(state)
	if len(rawCred) == 0 {
		// Render an error
		m := fiber.Map{
			"error": "No credential found",
		}
		return c.Render("displayerror", m)
	}

	claims := string(rawCred)

	// Create an access token from the credential
	accessToken, err := s.issuerVault.CreateAccessToken(claims, s.cfg.String("issuer.id"))
	if err != nil {
		return err
	}

	// Set it in a cookie
	cookie := new(fiber.Cookie)
	cookie.Name = "dbsamvf"
	cookie.Value = string(accessToken)
	cookie.Expires = time.Now().Add(1 * time.Hour)

	// Set cookie
	c.Cookie(cookie)

	// Set also the access token in the Authorization field of the response header
	bearer := "Bearer " + string(accessToken)
	c.Set("Authorization", bearer)

	// Render
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"claims":         claims,
		"prefix":         verifierPrefix,
	}
	return c.Render("verifier_receivedcredential", m)
}

func (s *Server) VerifierPageAccessProtectedService(c *fiber.Ctx) error {

	var code int
	var returnBody []byte
	var errors []error

	// Get the access token from the cookie
	accessToken := c.Cookies("dbsamvf")

	// Check if the user has configured a protected service to access
	protected := s.cfg.String("verifier.protectedResource.url")
	if len(protected) > 0 {

		// Prepare to GET to the url
		agent := fiber.Get(protected)

		// Set the Authentication header
		agent.Set("Authorization", "Bearer "+accessToken)

		agent.Set("accept", "application/json")
		code, returnBody, errors = agent.Bytes()
		if len(errors) > 0 {
			s.logger.Errorw("error calling SSI Kit", zap.Errors("errors", errors))
			return fmt.Errorf("error calling SSI Kit: %v", errors[0])
		}

	}

	// Render
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"accesstoken":    accessToken,
		"protected":      protected,
		"code":           code,
		"returnBody":     string(returnBody),
	}
	return c.Render("verifier_protectedservice", m)
}

// ##########################################
// ##########################################
// New Credential begin

func (s *Server) IssuerPageNewCredentialFormDisplay(c *fiber.Ctx) error {

	// Display the form to enter credential data
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"csrftoken":      c.Locals("csrftoken"),
		"prefix":         issuerPrefix,
	}

	return c.Render("issuer_newcredential", m)
}

type NewCredentialForm struct {
	FirstName  string `form:"firstName,omitempty"`
	FamilyName string `form:"familyName,omitempty"`
	Email      string `form:"email,omitempty"`
	Target     string `form:"target,omitempty"`
	Roles      string `form:"roles,omitempty"`
}

func (s *Server) IssuerPageNewCredentialFormPost(c *fiber.Ctx) error {

	// The user submitted the form. Get all the data
	newCred := &NewCredentialForm{}
	if err := c.BodyParser(newCred); err != nil {
		return err
	}

	m := fiber.Map{}

	// Display again the form if there are errors on input
	if newCred.Email == "" || newCred.FirstName == "" || newCred.FamilyName == "" ||
		newCred.Roles == "" || newCred.Target == "" {
		m["Errormessage"] = "Enter all fields"
		return c.Render("issuer_newcredential", m)
	}

	// Convert to the hierarchical map required for the template
	claims := fiber.Map{}

	claims["firstName"] = newCred.FirstName
	claims["familyName"] = newCred.FamilyName
	claims["email"] = newCred.Email

	names := strings.Split(newCred.Roles, ",")
	var roles []map[string]any
	role := map[string]any{
		"target": newCred.Target,
		"names":  names,
	}

	roles = append(roles, role)
	claims["roles"] = roles

	credentialData := fiber.Map{}
	credentialData["credentialSubject"] = claims

	// credID, _, err := srv.Operations.CreateServiceCredential(claims)
	// if err != nil {
	// 	return err
	// }

	// Get the issuer DID
	issuerDID, err := s.issuerVault.GetDIDForUser(s.cfg.String("issuer.id"))
	if err != nil {
		return err
	}

	// Call the issuer of SSI Kit
	agent := fiber.Post("http://localhost:7001/v1/credentials/issue")

	config := fiber.Map{
		"issuerDid":  issuerDID,
		"subjectDid": "did:key:z6Mkfdio1n9SKoZUtKdr9GTCZsRPbwHN8f7rbJghJRGdCt88",
		// "verifierDid": "theVerifier",
		// "issuerVerificationMethod": "string",
		"proofType": "LD_PROOF",
		// "domain":                   "string",
		// "nonce":                    "string",
		// "proofPurpose":             "string",
		// "credentialId":             "string",
		// "issueDate":                "2022-10-06T18:09:14.570Z",
		// "validDate":                "2022-10-06T18:09:14.570Z",
		// "expirationDate":           "2022-10-06T18:09:14.570Z",
		// "dataProviderIdentifier":   "string",
	}

	bodyRequest := fiber.Map{
		"templateId":     "PacketDeliveryService",
		"config":         config,
		"credentialData": credentialData,
	}

	out, _ := json.MarshalIndent(bodyRequest, "", "  ")
	fmt.Println(string(out))

	agent.JSON(bodyRequest)
	agent.ContentType("application/json")
	agent.Set("accept", "application/json")
	_, returnBody, errors := agent.Bytes()
	if len(errors) > 0 {
		s.logger.Errorw("error calling SSI Kit", zap.Errors("errors", errors))
		return fmt.Errorf("error calling SSI Kit: %v", errors[0])
	}

	parsed, err := yaml.ParseJson(string(returnBody))
	if err != nil {
		return err
	}

	credentialID := parsed.String("id")
	if len(credentialID) == 0 {
		s.logger.Errorw("id field not found in credential")
		return fmt.Errorf("id field not found in credential")
	}

	// Store credential
	_, err = s.issuerVault.Client.Credential.Create().
		SetID(credentialID).
		SetRaw([]uint8(returnBody)).
		Save(context.Background())
	if err != nil {
		s.logger.Errorw("error storing the credential", zap.Error(err))
		return err
	}

	str := prettyFormatJSON(returnBody)
	fmt.Println(str)

	// Render
	m = fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"claims":         str,
		"prefix":         issuerPrefix,
	}
	return c.Render("creddetails", m)
}

// New Credential end
// ##########################################
// ##########################################

func (s *Server) IssuerPageCredentialDetails(c *fiber.Ctx) error {

	// Get the ID of the credential
	credID := c.Params("id")

	claims, err := s.Operations.GetCredentialLD(credID)
	if err != nil {
		return err
	}

	// Render
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"claims":         claims,
		"prefix":         issuerPrefix,
	}
	return c.Render("creddetails", m)
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

// ##########################################
// ##########################################
//              APIS
// ##########################################
// ##########################################

// DID handling
func (srv *Server) CoreAPICreateDID(c *fiber.Ctx) error {

	// body := c.Body()

	// Call the SSI Kit
	agent := fiber.Post("http://localhost:7003/did/create")
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

	signatory := srv.cfg.String("ssikit.signatoryURL")
	fmt.Println("signatory", signatory)

	// Call the SSI Kit
	agent := fiber.Get(signatory + "/v1/templates")
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

	signatory := srv.cfg.String("ssikit.signatoryURL")
	fmt.Println("signatory", signatory)

	// Call the SSI Kit
	agent := fiber.Get(signatory + "/v1/templates/" + id)
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
