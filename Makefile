help:
	@echo "Look inside the Makefile to see what commands you can run"

credentials:
	go run cmd/creds/main.go

datamodel:
	go generate ./ent

issuer:
	go run cmd/issuers/main.go

cleandb:
	rm -f issuer.sqlite
	rm -f verifier.sqlite
	rm -f wallet.sqlite

serve:
	go run .