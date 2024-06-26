# psso-server-go

Welcome to psso-server-go. It is a basic implementation of the Platform Single Sign on protocol. The protocol implementation is handed by psso-pkg-go.  psso-server-go calls implement the user and session management, groups, and web-specific calls. The package handles the cryptography, JWT, and other protocol-specific features.  

## PSSO
PSSO is a feature of macOS for cloud binding. It provides a mechanism for 
To learn more about Platform SSO (PSSO), please visit https://twocanoes.com/sso.

## Running
psso-server-go should be able to be deployed on macOS, Windows, and Linux. PSSO requires that the service use TLS with a public SSL certificate (Let's Encrypt works fine). The basic steps are:

1. Install Go and Git on your target platform
2. Register a DNS name and get a certificate from a well known authority
3. Clone the repo to the target machine:

	`git clone https://github.com/twocanoes/psso-server-go`
		
4. Run go mod tidy to get the required packages:
		
	`go mod tidy`

5. Run the app. The defaults assume a folder writeable by the app /var/psso. The defaults are set for macOS and Linux and should be modified as outlined in the Modifying Defaults section.

	go run cmd/local/main.go
		
6. Create a configuration profile and SSOE app in macOS to use this service. Please see https://twocanoes.com/sso for further information.


## Modifying Defaults

Set up the environment variables for the service configuration:

_PSSO_ISSUER_ (example.com): Issuer. Used for Iss in JWT.

_PSSO_AUDIENCE_ (psso): Audience. Used for Aud in JWT.

_PSSO_ADDRESS_ (:6443): Network address and port to listen on.

_PSSO_JWKSFILEPATH_ (/var/psso/jwks.json): Path to JSON file where the service keys will be created and stored.

_PSSO_TLSPRIVATEKEYPATH_ (/etc/psso/privkey.pem): Path to TLS certificate in PEM format.

_PSSO_TLSCERTIFICATECHAINPATH_ (/etc/psso/fullchain.pem): Path to folder where device keys are stored. Each registered device will be in its own file in this folder.

_PSSO_DEVICEFILEPATH_: /var/psso/devices): Path to folder where device keys

_PSSO_NONCEPATH_: /var/psso/nonce): Path to folder where nonce are stored. Each nonce will be in its own file in this folder.

_PSSO_KEYPATH_ (/var/psso/keys): Path to folder where device keys are stored. Each device key will be in its own file in this folder. This file is used to look up the device file when a key id is given.

_PSSO_ENDPOINTNONCE_ (/psso/nonce): HTTP endpoint where the client requests a nonce.

_PSSO_ENDPOINTREGISTER_ (/psso/register): HTTP endpoint where client registers a new device

_PSSO_ENDPOINTTOKEN_ (/psso/token): HTTP token where client posts JWT tokens

_PSSO_ENDPOINTJWKS_ (/psso/.well-known/jwks.json): HTTP endpoint for advertising the public key for the PSSO service.


## Thanks
Thanks to Joel Rennich for his deep dive into figuring out the details of PSSO and providing guidance on how this all works.
