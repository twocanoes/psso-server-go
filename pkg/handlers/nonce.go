package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/twocanoes/psso-server/pkg/constants"
	"github.com/twocanoes/psso-server/pkg/file"
)

type NonceResponse struct {
	Nonce string
}

func Nonce() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		fmt.Println("Request for /nonce")

		nonceBytes := make([]byte, 32)
		_, err := rand.Read(nonceBytes)

		if err != nil {
			http.Error(w, "bad nonce request", http.StatusBadRequest)
		}

		response := NonceResponse{
			Nonce: base64.StdEncoding.EncodeToString(nonceBytes),
		}
		nonce := file.Nonce{
			Nonce:    base64.StdEncoding.EncodeToString(nonceBytes),
			Category: "nonce",
			TTL:      int(time.Now().Unix()) + (5 * 60), // make nonce good for 5 mins

		}

		nonceString := hex.EncodeToString(nonceBytes) + ".json"
		err = file.Save(nonce, filepath.Join(constants.NoncePath, nonceString))

		if err != nil {
			fmt.Println(err)
			return
		}
		json, _ := json.Marshal(response)
		w.Write(json)
	}
}
