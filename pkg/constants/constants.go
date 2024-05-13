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
	BaseURL                 = "https://idp.twocanoes.com/psso"
	Port                    = "6443"
	Address                 = ":6443"
	TLSPrivateKeyPath       = getEnv("TLSPrivateKeyPath", filepath.FromSlash("/etc/letsencrypt/live/idp.twocanoes.com/privkey.pem"))
	TLSCertificateChainPath = getEnv("TLSCertificateChainPath", filepath.FromSlash("/etc/letsencrypt/live/idp.twocanoes.com/fullchain.pem"))
	JWKSFilepath            = getEnv("JWKSFilepath", filepath.FromSlash("/var/psso/jwks.json"))
	DeviceFilePath          = getEnv("DeviceFilePath", filepath.FromSlash("/var/psso/devices"))
	NoncePath               = getEnv("NoncePath", filepath.FromSlash("/var/psso/nonce"))
	KeyPath                 = getEnv("KeyPath", filepath.FromSlash("/var/psso/keys"))

	EndpointJWKS           = getEnv("EndpointJWKS", "/.well-known/jwks.json")
	EndpointAppleSiteAssoc = getEnv("EndpointAppleSiteAssoc", "/.well-known/apple-app-site-association")
	EndpointNonce          = getEnv("EndpointNonce", "/nonce")
	EndpointRegister       = getEnv("EndpointRegister", "/register")
	EndpointToken          = getEnv("EndpointToken", "/token")
)

func getEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}
