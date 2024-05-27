package handlers

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/twocanoes/psso-sdk-go/psso"
	"github.com/twocanoes/psso-server/pkg/constants"
	"github.com/twocanoes/psso-server/pkg/file"
)

func jwksPrivateKey() (*ecdsa.PrivateKey, error) {

	jwks, err := file.GetJWKS()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	jwkPrivKey, err := jwks.PrivateKey()
	if err != nil {
		fmt.Printf("%v", err)
		return nil, err
	}

	return jwkPrivKey, nil

}
func Token() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Request for /token")

		//get keystore for service private key and key id.
		jwks, err := file.GetJWKS()
		if err != nil {
			fmt.Println(err)
			return
		}

		//get the service private key for signing response.
		servicePrivateKey, err := jwksPrivateKey()
		if err != nil {
			fmt.Println(err)
			return
		}

		// // Dump the request to see what we have here
		// requestDump, err := httputil.DumpRequest(r, true)
		// if err != nil {
		// 	fmt.Println(err)
		// 	return
		// }
		// log.Write(string(requestDump)).Debug()

		//make sure we have a post since that is the only http verb allowed at this endpoint.
		if r.Method != "POST" {
			fmt.Println("message not a POST")
			return
		}

		//The response for has the PSSO version and the token.
		r.ParseForm()

		// assertion or request?
		requestJWTString := r.FormValue("assertion")

		if requestJWTString == "" {
			requestJWTString = r.FormValue("request")

		}
		//need to get the headers so we parse the JWT and pull out the key ID.
		requestJWT, err := jwt.ParseSigned(requestJWTString)

		if err != nil {
			fmt.Println(err)
			return
		}

		//The key id from the request is used to look up the device so we can use the device keys.
		kid := requestJWT.Headers[0].KeyID
		if kid == "" {
			return
		}
		var keyID file.KeyID

		filePath, err := base64.StdEncoding.DecodeString(kid)

		if err != nil {
			fmt.Println(err)
			return

		}
		keyIDData, err := file.ReadFile(filepath.Join(constants.KeyPath, hex.EncodeToString(filePath)+".json"))
		if err != nil {
			fmt.Println(err)

			return

		}
		err = json.Unmarshal(keyIDData, &keyID)

		if err != nil {
			fmt.Println(err)
			return
		}

		if keyID.PEM == "" {
			fmt.Println("bad conversion to key id")
			return
		}

		// Pull out the device signing public key PEM and turn it into a key.
		// the device public key is used to verify the signature of the request JWT.

		deviceSigningPublicKey, err := psso.ECPublicKeyFromPEM(keyID.PEM)
		if err != nil {
			fmt.Println("invalid ECPublicKeyFromPEM")
			return

		}

		deviceID := keyID.Device

		var device file.Device

		deviceData, err := file.ReadFile(filepath.Join(constants.DeviceFilePath, deviceID+".json"))

		if err != nil {
			fmt.Println("ReadFile error")
			return

		}

		err = json.Unmarshal(deviceData, &device)

		if err != nil {
			fmt.Println("Unmarshal error")
			return

		}
		if device.EncryptionKey == "" {
			fmt.Println("Unable to get device encryption key")
			return
		}

		deviceEncryptionKeyBytes := []byte(device.EncryptionKey)

		deviceEncryptionKeyBlock, _ := pem.Decode(deviceEncryptionKeyBytes)
		deviceEncryptionPublicKey, _ := x509.ParsePKIXPublicKey(deviceEncryptionKeyBlock.Bytes)

		pssoVersion := r.FormValue("platform_sso_version")

		var jweString string
		// The version of PSSO is required to be known since the format of the claims is different depending on the version
		// of PSSO.
		if pssoVersion == "1.0" {

			//verify the signature and get the claims for the user authentication.
			userClaims, _, err := psso.VerifyJWTAndReturnUserClaims(requestJWTString, deviceSigningPublicKey)

			if err != nil {
				fmt.Println(err)
				return
			}
			//get the username and password sent in thte request
			claimUsername := userClaims.Username
			claimPassword := userClaims.Password

			// compare with what is passed in
			if claimUsername == "jappleseed@twocanoes.com" && claimPassword == "twocanoes" {

				jweString, err = psso.CreateIDTokenResponse(constants.Issuer, *userClaims, "johnny", "Johnny Appleseed", []string{"admin", "net-admin", "software-install"}, "jappleseed@twocanoes.com", "jappleseed@twocanoes.com", "refresh", servicePrivateKey, jwks.KID, deviceEncryptionPublicKey.(*ecdsa.PublicKey))
				if err != nil {
					fmt.Println("invalid jwe")
					return
				}

			} else if claimUsername == "liz@twocanoes.com" && claimPassword == "twocanoes" {

				jweString, err = psso.CreateIDTokenResponse(constants.Issuer, *userClaims, "Liz", "Liz Appleseed", []string{"software-install", "psso-standard-users"}, "liz@twocanoes.com", "liz@twocanoes.com", "refresh", servicePrivateKey, jwks.KID, deviceEncryptionPublicKey.(*ecdsa.PublicKey))
				if err != nil {
					fmt.Println("invalid jwe")
					return
				}

			} else if claimUsername == "nate@twocanoes.com" && claimPassword == "twocanoes" {

				jweString, err = psso.CreateIDTokenResponse(constants.Issuer, *userClaims, "Nate", "Nate Appleseed", []string{"software-install", "psso-standard-users"}, "nate@twocanoes.com", "nate@twocanoes.com", "refresh", servicePrivateKey, jwks.KID, deviceEncryptionPublicKey.(*ecdsa.PublicKey))
				if err != nil {
					fmt.Println("invalid jwe")
					return
				}

			} else {
				fmt.Println("invalid username or password")
				return
			}

		} else if pssoVersion == "2.0" {

			fmt.Println("Message is v2")
			keyRequestClaims, err := psso.VerifyJWTAndReturnKeyRequestClaims(requestJWTString, deviceSigningPublicKey)

			if err != nil {
				fmt.Println("invalid username or password")
				return
			}
			fmt.Println("decrypting symmetric key.")
			keyExchangePasswordData, err := base64.StdEncoding.DecodeString(device.KeyExchangeKey)

			if err != nil {
				fmt.Println(err)
				return

			}
			if keyRequestClaims.RequestType == "key_request" {
				fmt.Println("key_request")

				jweString, err = psso.CreateKeyRequestResponseClaims(*keyRequestClaims, deviceEncryptionPublicKey.(*ecdsa.PublicKey), keyExchangePasswordData)
				if err != nil {
					fmt.Println(err)
					return
				}

			} else if keyRequestClaims.RequestType == "key_exchange" {

				jweString, err = psso.CreateKeyExchangeResponseClaims(*keyRequestClaims, deviceEncryptionPublicKey.(*ecdsa.PublicKey), keyExchangePasswordData)

				if err != nil {
					fmt.Println(err)
					return
				}
			} else {
				fmt.Println("invalid request type")
				return

			}
		} else {

			fmt.Println("invalid PSSO version")
			return
		}

		w.Header().Set("Content-Type", "application/platformsso-login-response+jwt; charset=utf-8")
		w.Write([]byte(jweString))

	}
}
