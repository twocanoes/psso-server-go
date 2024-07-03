# psso-server-go

Welcome to psso-server-go. It is a basic implementation of the Platform Single Sign on protocol. The protocol implementation is handed by psso-pkg-go.  psso-server-go calls implement the user and session management, groups, and web-specific calls. The package handles the cryptography, JWT, and other protocol-specific features.  

## PSSO
PSSO is a feature of macOS for cloud binding. It provides a mechanism for 
To learn more about Platform SSO (PSSO), please visit https://twocanoes.com/sso.

## Running
psso-server-go should be able to be deployed on macOS, Windows, and Linux. PSSO requires that the service use TLS with a public SSL certificate (Let's Encrypt works fine). The basic steps are:

1. Install Go (https://golang.com) and Git (xcode-select --install on macOS) on your target platform

2. Register a DNS name and get a certificate from a well known authority. Make sure the private key and certificate are in PEM format and are not password protected. Copy the private key to /etc/psso/privkey.pem and the certificate chain to /etc/psso/fullchain.pem. The server certificate should listed first and the root certificate in the chain listed last in the fullchain.pem.
3. Clone the repo to the target machine:

	`git clone https://github.com/twocanoes/psso-server-go`
			
4. Run go mod tidy to get the required packages:
			
	`go mod tidy`

5. Run the app. The defaults assume a folder writeable by the app /var/psso. The defaults are set for macOS and Linux and should be modified as outlined in the Modifying Defaults section. Set the PSSO\_ISSUER to the hostname of the service. It must match the Issuer in the configuration profile below.

	```xml
	sudo -s
	PSSO_ISSUER=idp.example.com go run cmd/local/main.go
	```

6. If the hostname is not accessible via DNS on the client, add the hostname and the IP address to the /etc/hosts file, replacing idp.example.com with the hostname of the PSSO server.

`sudo -s`
```xml
echo "192.168.1.100 idp.example.com" >> /etc/hosts
```

6. On the client, verify these endpoints are accessible (replace idp.example.com with your hostname) and do not have any SSL errors.
https://idp.example.com/.well-known/apple-app-site-association
https://idp.example.com/.well-known/jwks.json
		
6. Install Scissors test app from:

> https://github.com/twocanoes/sso/releases/
		
6. Create a configuration profile and SSOE app in macOS to use this service. Replace the following key/values:

* AccountDisplayName: name of the Identity Provider that will show in dialogs. For example, "My Identity Provider".
* BaseURL: The URL of the service. For example, https://idp.example.com.
* Issuer: the hostname. It must match the issuer when running. For example, idp.example.com.
 
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">~
<dict>
<key>PayloadContent</key>
<array>
	<dict>
		<key>AuthenticationMethod</key>
		<string>Password</string>
		<key>ExtensionIdentifier</key>
		<string>com.twocanoes.Scissors.ssoe</string>
		<key>PayloadDisplayName</key>
		<string>Single Sign-On Extensions Scissors</string>
		<key>PayloadIdentifier</key>
		<string>com.apple.extensiblesso.CA351D35-96B1-41CF-B25B-DF3273189AAD</string>
		<key>PayloadOrganization</key>
		<string></string>
		<key>PayloadType</key>
		<string>com.apple.extensiblesso</string>
		<key>PayloadUUID</key>
		<string>4B7148CD-1069-4140-95CE-78F61BCD9C2B</string>
		<key>PayloadVersion</key>
		<integer>1</integer>
		<key>PlatformSSO</key>
		<dict>
			<key>AccountDisplayName</key>
			<string>My Identity Provider</string>
			<key>AuthenticationMethod</key>
			<string>Password</string>
			<key>EnableAuthorization</key>
			<true/>
			<key>EnableCreateUserAtLogin</key>
			<true/>
			<key>NewUserAuthorizationMode</key>
			<string>Groups</string>
			<key>UseSharedDeviceKeys</key>
			<true/>
			<key>UserAuthorizationMode</key>
			<string>Groups</string>
		</dict>
		<key>TeamIdentifier</key>
		<string>UXP6YEHSPW</string>
		<key>Type</key>
		<string>Redirect</string>
	</dict>
	<dict>
		<key>BaseURL</key>
		<string>https://idp.example.com/</string>
		<key>Issuer</key>
		<string>idp.example.com</string>
		<key>Audience</key>
		<string>idp-audience</string>
		<key>ClientID</key>
		<string>idp-clientid</string>
		<key>PayloadDisplayName</key>
		<string>Scissors SSOE</string>
		<key>PayloadIdentifier</key>
		<string>mdscentral.00A38C42-503B-4016-A86D-2186CDA5989C.com.twocanoes.xcreds.3E7FAF27-6179-46AA-B1A3-B55E08D3273D</string>
		<key>PayloadOrganization</key>
		<string></string>
		<key>PayloadType</key>
		<string>com.twocanoes.Scissors.ssoe</string>
		<key>PayloadUUID</key>
		<string>3E7FAF27-6179-46AA-B1A3-B55E08D3273D</string>
		<key>PayloadVersion</key>
		<integer>1</integer>
	</dict>
</array>
<key>PayloadDisplayName</key>
<string>PSSO</string>
<key>PayloadIdentifier</key>
<string>mdscentral.00A38C42-503B-4016-A86D-2186CDA5989C</string>
<key>PayloadOrganization</key>
<string></string>
<key>PayloadScope</key>
<string>System</string>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadUUID</key>
<string>851A1B56-6A8A-442B-91CB-BC12FF416766</string>
<key>PayloadVersion</key>
<integer>1</integer>
</dict>
</plist>
```

## Modifying Defaults

Set up the environment variables for the service configuration:

_PSSO\_ISSUER_ Issuer (required, no default value. Usually URL to IdP like https://idp.example.com). Used for Iss in JWT. Must match the Issuer key in the config profile for the sample app "Scissors" or issuer in ASAuthorizationProviderExtensionLoginConfiguration as shown below:

> let config = ASAuthorizationProviderExtensionLoginConfiguration(clientID:clientID , issuer: *issuer*, tokenEndpointURL: tokenEndpoint, jwksEndpointURL: jwksEndpoint, audience: audience)


_PSSO\_AUDIENCE_ (psso): Audience. Used for Aud in JWT.

_PSSO\_ADDRESS_ (:6443): Network address and port to listen on.

_PSSO\_JWKSFILEPATH_ (/var/psso/jwks.json): Path to JSON file where the service keys will be created and stored.

_PSSO\_TLSPRIVATEKEYPATH_ (/etc/psso/privkey.pem): Path to TLS certificate in PEM format.

_PSSO\_TLSCERTIFICATECHAINPATH_ (/etc/psso/fullchain.pem): Path to folder where device keys are stored. Each registered device will be in its own file in this folder.

_PSSO\_DEVICEFILEPATH_: /var/psso/devices): Path to folder where device keys

_PSSO\_NONCEPATH_: /var/psso/nonce): Path to folder where nonce are stored. Each nonce will be in its own file in this folder.

_PSSO\_KEYPATH_ (/var/psso/keys): Path to folder where device keys are stored. Each device key will be in its own file in this folder. This file is used to look up the device file when a key id is given.

_PSSO\_ENDPOINTNONCE_ (/psso/nonce): HTTP endpoint where the client requests a nonce.

_PSSO\_ENDPOINTREGISTER_ (/psso/register): HTTP endpoint where client registers a new device

_PSSO\_ENDPOINTTOKEN_ (/psso/token): HTTP token where client posts JWT tokens

_PSSO\_ENDPOINTJWKS_ (/psso/.well-known/jwks.json): HTTP endpoint for advertising the public key for the PSSO service.


## Thanks
Thanks to Joel Rennich for his deep dive into figuring out the details of PSSO and providing guidance on how this all works.