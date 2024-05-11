package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/twocanoes/psso-sdk-go/psso"
	"github.com/twocanoes/psso-server/pkg/constants"
	"github.com/twocanoes/psso-server/pkg/file"
)

var jsonJWKS JSONJWKS
var currentAASA JSONAASA

type JSONAuthServe struct {
	Apps []string `json:"apps"`
}

type JSONAASA struct {
	AuthServ JSONAuthServe `json:"authsrv"`
}

type JSONJWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Curve     string `json:"crv"`
	KeyID     string `json:"kid"`
	X         string `json:"x"`
	Y         string `json:"y"`
	Algorithm string `json:"alg"`
}

type JSONJWKS struct {
	Keys []JSONJWK `json:"keys"`
}

func CheckWellKnowns() {

	var jwks psso.JWKS
	fmt.Println("Checking JWKS")

	tJwks, err := file.GetJWKS()
	if err != nil {
		panic(err)
	}
	jwks = *tJwks

	jsonJWK := JSONJWK{
		KeyType:   "EC",
		Use:       "sig",
		Curve:     "P-256",
		Algorithm: "ES256",
		KeyID:     jwks.KID,
		X:         jwks.X,
		Y:         jwks.Y,
	}

	jsonJWKS = JSONJWKS{
		Keys: []JSONJWK{jsonJWK},
	}

	// build AASA

	currentAASA = JSONAASA{
		AuthServ: JSONAuthServe{
			Apps: constants.AASAApps[:],
		},
	}
}

func WellKnownJWKS() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// // Dump the request to see what we have here
		// requestDump, err := httputil.DumpRequest(r, true)
		// if err != nil {
		// 	fmt.Println(err)
		// }
		// fmt.Println(string(requestDump))

		fmt.Println("Request for .well-known/jwks.json")
		response, _ := json.Marshal(jsonJWKS)
		w.Write(response)
	}
}

func WellKnownAASA() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Dump the request to see what we have here
		requestDump, err := httputil.DumpRequest(r, true)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(string(requestDump))

		fmt.Println("Request for .well-known/apple-app-site-association")
		response, _ := json.Marshal(currentAASA)
		w.Write(response)
	}
}
