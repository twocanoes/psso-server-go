package file

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/twocanoes/psso-sdk-go/psso"
	"github.com/twocanoes/psso-server/pkg/constants"
)

type Device struct {
	Device         string
	Category       string
	SigningKey     string
	EncryptionKey  string
	KeyExchangeKey string
	CreationTime   int
}
type KeyID struct {
	KeyID        string
	Device       string
	CreationTime int
	PEM          string
}
type Nonce struct {
	Nonce    string
	Category string
	TTL      int
	Device   string
	User     string
}

func Save(object interface{}, path string) error {
	parentFolder := filepath.Dir(path)

	if _, err := os.Stat(parentFolder); errors.Is(err, os.ErrNotExist) {
		os.Mkdir(parentFolder, 0750)
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) == false {
		fmt.Println("Removing file")
		err = os.Remove(path)
		if err != nil {
			return err
		}
	}

	marshalledData, err := json.Marshal(object)

	if err != nil {
		fmt.Println("error marshalledData")
		return err
	}

	fo, err := os.Create(path)

	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	// close fo on exit and check for its returned error
	defer func() {
		if err := fo.Close(); err != nil {
			fmt.Println(err)
			panic(err)
		}
	}()

	_, err = fo.Write(marshalledData)
	return err

}

func ReadFile(path string) ([]byte, error) {

	fi, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file in ReadFile")
	}
	// close fi on exit and check for its returned error
	defer func() {
		if err := fi.Close(); err != nil {
			fmt.Println(err)
			panic(err)
		}
	}()

	buf := make([]byte, 1024)

	bytesRead, err := fi.Read(buf)

	if err != nil {

		fmt.Println("error reading file")
		return nil, fmt.Errorf("error reading file")

	}

	return buf[0:bytesRead], nil

}
func GetJWKS() (*psso.JWKS, error) {
	if _, err := os.Stat(constants.JWKSFilepath); errors.Is(err, os.ErrNotExist) {

		fmt.Println("No flat file JWKS stored, creating one")
		jwks, err := psso.CreateJWKS()

		if err != nil {
			fmt.Println("error making key")
			return nil, err
		}

		err = Save(jwks, constants.JWKSFilepath)
		// _, err = fo.Write(marshalledData)

		if err != nil {
			return nil, fmt.Errorf("error creating jwks")
		}
		return jwks, nil

	} else {
		fmt.Println("jwks file exists. reading")

		data, err := ReadFile(constants.JWKSFilepath)

		if err != nil {

			fmt.Println("error reading file")
			return nil, fmt.Errorf("error reading file")

		}

		var jwks = &psso.JWKS{}
		err = json.Unmarshal(data, &jwks)

		if err != nil {
			return nil, fmt.Errorf("error Unmarshal file")

		}
		return jwks, nil

	}
}
