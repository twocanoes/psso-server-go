package constants

import (
	"os"
	"path/filepath"
)

var AASAApps = [...]string{
	"UXP6YEHSPW.com.twocanoes.ssoeexample",
	"UXP6YEHSPW.com.twocanoes.sciSSOrs",
	"UXP6YEHSPW.com.twocanoes.Scissors",
}

var (
	Issuer                  = getEnv("PSSO_ISSUER", "")
	Audience                = getEnv("PSSO_AUDIENCE", "psso")
	Address                 = getEnv("PSSO_ADDRESS", ":443")
	TLSPrivateKeyPath       = getEnv("PSSO_TLSPRIVATEKEYPATH", filepath.FromSlash("/etc/psso/privkey.pem"))
	TLSCertificateChainPath = getEnv("PSSO_TLSCERTIFICATECHAINPATH", filepath.FromSlash("/etc/psso/fullchain.pem"))
	JWKSFilepath            = getEnv("PSSO_JWKSFILEPATH", filepath.FromSlash("/var/psso/jwks.json"))
	DeviceFilePath          = getEnv("PSSO_DEVICEFILEPATH", filepath.FromSlash("/var/psso/devices"))
	NoncePath               = getEnv("PSSO_NONCEPATH", filepath.FromSlash("/var/psso/nonce"))
	KeyPath                 = getEnv("PSSO_KEYPATH", filepath.FromSlash("/var/psso/keys"))

	EndpointJWKS           = getEnv("PSSO_ENDPOINTJWKS", "/.well-known/jwks.json")
	EndpointAppleSiteAssoc = getEnv("PSSO_ENDPOINTAPPLESITEASSOC", "/.well-known/apple-app-site-association")
	EndpointNonce          = getEnv("PSSO_ENDPOINTNONCE", "/nonce")
	EndpointRegister       = getEnv("PSSO_ENDPOINTREGISTER", "/register")
	EndpointToken          = getEnv("PSSO_ENDPOINTTOKEN", "/token")
)

func getEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}
