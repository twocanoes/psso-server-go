package constants

var AASAApps = [...]string{
	"UXP6YEHSPW.com.twocanoes.ssoeexample",
	"UXP6YEHSPW.com.twocanoes.sciSSOrs",
	"UXP6YEHSPW.com.twocanoes.Scissors",
}

const (
	BaseURL                 = "https://idp.twocanoes.com/psso"
	Port                    = "6443"
	Address                 = ":6443"
	TLSPrivateKeyPath       = "/etc/letsencrypt/live/idp.twocanoes.com/privkey.pem"
	TLSCertificateChainPath = "/etc/letsencrypt/live/idp.twocanoes.com/fullchain.pem"
	JWKSFilepath            = "/var/psso/jwks.json"
	DeviceFilePath          = "/var/psso/devices"
	NoncePath               = "/var/psso/nonce"
	KeyPath                 = "/var/psso/keys"

	EndpointJWKS           = "/.well-known/jwks.json"
	EndpointAppleSiteAssoc = "/.well-known/apple-app-site-association"
	EndpointNonce          = "/nonce"
	EndpointRegiseter      = "/register"
	EndpointToken          = "/token"
)
