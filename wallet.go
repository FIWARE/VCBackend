package main

import (
	"context"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

type Wallet struct {
	server *Server
}

// setupEnterpriseWallet sreates and setups the Enterprise Wallet routes
func setupEnterpriseWallet(s *Server) {

	wallet := &Wallet{s}

	// Define the prefix for Wallet routes
	walletRoutes := s.Group(walletPrefix)

	// Page to display the available credentials (from the Issuer)
	walletRoutes.Get("/selectcredential", wallet.WalletPageSelectCredential)

	// To send a credential to the Verifier
	walletRoutes.Get("/sendcredential", wallet.WalletPageSendCredential)

}

func (w *Wallet) WalletPageSelectCredential(c *fiber.Ctx) error {

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
	credsSummary, err := w.server.Operations.GetAllCredentials()
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

func (w *Wallet) WalletPageSendCredential(c *fiber.Ctx) error {

	// Get the ID of the credential
	credID := c.Query("id")
	w.server.logger.Info("credID", credID)

	// Get the url where we have to send the credential
	redirect_uri := c.Query("redirect_uri")
	w.server.logger.Info("redirect_uri", redirect_uri)

	// Get the state nonce
	state := c.Query("state")
	w.server.logger.Info("state", state)

	// Get the raw credential from the Vault
	// TODO: change to the vault of the wallet without relying on the issuer
	rawCred, err := w.server.issuerVault.Client.Credential.Get(context.Background(), credID)
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
		w.server.logger.Errorw("error sending credential", zap.Errors("errors", errors))
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

func (w *Wallet) WalletAPICreatePresentation(creds []string, holder string) (string, error) {

	type inputCreatePresentation struct {
		Vcs       []string `json:"vcs,omitempty"`
		HolderDid string   `json:"holderDid,omitempty"`
	}

	postBody := inputCreatePresentation{
		Vcs:       creds,
		HolderDid: holder,
	}

	custodianURL := w.server.cfg.String("ssikit.custodianURL")

	// Call the SSI Kit
	agent := fiber.Post(custodianURL + "/credentials/present")
	agent.Set("accept", "application/json")
	agent.JSON(postBody)
	_, returnBody, errors := agent.Bytes()
	if len(errors) > 0 {
		w.server.logger.Errorw("error calling SSI Kit", zap.Errors("errors", errors))
		return "", fmt.Errorf("error calling SSI Kit: %v", errors[0])
	}

	fmt.Println("presentation", string(returnBody))

	return string(returnBody), nil

}
