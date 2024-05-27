package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/twocanoes/psso-server/pkg/constants"
	"github.com/twocanoes/psso-server/pkg/file"
)

type PSSORegistration struct {
	DeviceUUID          string `json:"DeviceUUID"`
	DeviceSigningKey    string `json:"DeviceSigningKey"`
	DeviceEncryptionKey string `json:"DeviceEncryptionKey"`
	SignKeyID           string `json:"SignKeyID"`
	EncKeyID            string `json:"EncKeyID"`
	// User                string `json:"user,omitempty"`
}

func Register() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		fmt.Println("Request for /register")
		// Dump the request to see what we have here
		// requestDump, err := httputil.DumpRequest(r, true)
		// if err != nil {
		// 	fmt.Println(err)
		// }

		// fmt.Println(string(requestDump))

		if r.Method != "POST" {
			return
		}

		// Use http.MaxBytesReader to enforce a maximum read of 1MB from the
		// response body. A request body larger than that will now result in
		// Decode() returning a "http: request body too large" error.
		r.Body = http.MaxBytesReader(w, r.Body, 1048576)

		// Setup the decoder and call the DisallowUnknownFields() method on it.
		// This will cause Decode() to return a "json: unknown field ..." error
		// if it encounters any extra unexpected fields in the JSON. Strictly
		// speaking, it returns an error for "keys which do not match any
		// non-ignored, exported fields in the destination".
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var request PSSORegistration

		err := dec.Decode(&request)

		if err != nil {
			var syntaxError *json.SyntaxError
			var unmarshalTypeError *json.UnmarshalTypeError

			switch {
			// Catch any syntax errors in the JSON and send an error message
			// which interpolates the location of the problem to make it
			// easier for the client to fix.
			case errors.As(err, &syntaxError):
				msg := fmt.Sprintf("Request body contains badly-formed JSON (at position %d)", syntaxError.Offset)
				http.Error(w, msg, http.StatusBadRequest)

			// In some circumstances Decode() may also return an
			// io.ErrUnexpectedEOF error for syntax errors in the JSON. There
			// is an open issue regarding this at
			// https://github.com/golang/go/issues/25956.
			case errors.Is(err, io.ErrUnexpectedEOF):
				msg := "Request body contains badly-formed JSON"
				http.Error(w, msg, http.StatusBadRequest)

			// Catch any type errors, like trying to assign a string in the
			// JSON request body to a int field in our Person struct. We can
			// interpolate the relevant field name and position into the error
			// message to make it easier for the client to fix.
			case errors.As(err, &unmarshalTypeError):
				msg := fmt.Sprintf("Request body contains an invalid value for the %q field (at position %d)", unmarshalTypeError.Field, unmarshalTypeError.Offset)
				http.Error(w, msg, http.StatusBadRequest)

			// Catch the error caused by extra unexpected fields in the request
			// body. We extract the field name from the error message and
			// interpolate it in our custom error message. There is an open
			// issue at https://github.com/golang/go/issues/29035 regarding
			// turning this into a sentinel error.
			case strings.HasPrefix(err.Error(), "json: unknown field "):
				fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
				msg := fmt.Sprintf("Request body contains unknown field %s", fieldName)
				http.Error(w, msg, http.StatusBadRequest)

			// An io.EOF error is returned by Decode() if the request body is
			// empty.
			case errors.Is(err, io.EOF):
				msg := "Request body must not be empty"
				http.Error(w, msg, http.StatusBadRequest)

			// Catch the error caused by the request body being too large. Again
			// there is an open issue regarding turning this into a sentinel
			// error at https://github.com/golang/go/issues/30715.
			case err.Error() == "http: request body too large":
				msg := "Request body must not be larger than 1MB"
				http.Error(w, msg, http.StatusRequestEntityTooLarge)

			// Otherwise default to logging the error and sending a 500 Internal
			// Server Error response.
			default:
				fmt.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		fmt.Println("Storing device: " + request.DeviceUUID)

		keyExchangeKeyBytes := make([]byte, 32)
		rand.Read(keyExchangeKeyBytes)

		newDevice := file.Device{
			Device:         request.DeviceUUID,
			Category:       "pssodevice",
			SigningKey:     request.DeviceSigningKey,
			EncryptionKey:  request.DeviceEncryptionKey,
			KeyExchangeKey: base64.StdEncoding.EncodeToString(keyExchangeKeyBytes),
			CreationTime:   int(time.Now().Unix()),
		}
		err = file.Save(newDevice, filepath.Join(constants.DeviceFilePath, request.DeviceUUID+".json"))

		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		fmt.Println("Saving signing and encryption keys")
		newSignKey := file.KeyID{
			KeyID:        request.SignKeyID,
			Device:       request.DeviceUUID,
			CreationTime: int(time.Now().Unix()),
			PEM:          request.DeviceSigningKey,
		}

		decodedSigningKeyID, err := base64.StdEncoding.DecodeString(request.SignKeyID)

		if err != nil {

			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		filename := hex.EncodeToString(decodedSigningKeyID) + ".json"

		err = file.Save(newSignKey, filepath.Join(constants.KeyPath, filename))

		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		newEncKey := file.KeyID{
			KeyID:        request.EncKeyID,
			Device:       request.DeviceUUID,
			CreationTime: int(time.Now().Unix()),
			PEM:          request.DeviceSigningKey,
		}

		decodedEncryptionKeyID, err := base64.StdEncoding.DecodeString(request.EncKeyID)

		if err != nil {

			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		filename = hex.EncodeToString(decodedEncryptionKeyID) + ".json"

		err = file.Save(newEncKey, filepath.Join(constants.KeyPath, filename+".json"))

		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}
}
