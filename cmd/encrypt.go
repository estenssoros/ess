package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var (
	encryptKeyFile    string
	encryptInputFile  string
	encryptOutputFile string
)

func init() {
	encryptCmd.Flags().StringVarP(&encryptKeyFile, "key", "k", "", "key file")
	encryptCmd.Flags().StringVarP(&encryptInputFile, "input", "i", "", "input file to encrypt")
	encryptCmd.Flags().StringVarP(&encryptOutputFile, "output", "o", "", "output file to write data")
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "encrypt a file using a public key",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if encryptKeyFile == "" {
			homeDir, err := homedir.Dir()
			if err != nil {
				return errors.Wrap(err, "homedir.Dir")
			}
			decryptKeyFile = filepath.Join(homeDir, "/.ssh/id_rsa.pub")
		}
		if encryptInputFile == "" {
			return errors.New("missing input file")
		}
		if encryptOutputFile == "" {
			return errors.New("missing output file")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		bs, err := ioutil.ReadFile(encryptInputFile)
		if err != nil {
			return errors.Wrap(err, "ioutil.ReadFile")
		}
		encrypted, err := encrypt(bs, encryptKeyFile)
		if err != nil {
			return errors.Wrap(err, "encrypt")
		}
		f, err := os.Create(encryptOutputFile)
		if err != nil {
			return errors.Wrap(err, "os.Create")
		}
		defer f.Close()
		_, err = f.Write(encrypted)
		return errors.Wrap(err, "f.Write")
	},
}

func encrypt(msg []byte, keyFile string) ([]byte, error) {
	bs, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, errors.Wrap(err, "ioutil.ReadFile")
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(bs)
	if err != nil {
		return nil, errors.Wrap(err, "ssh.ParseAuthorizedKey")
	}

	parsedCryptoKey, ok := parsed.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.Errorf("parsed is %T", parsed)
	}

	pubCrypto := parsedCryptoKey.CryptoPublicKey()

	pub, ok := pubCrypto.(*rsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("pubCrypto is %T not rsa.PublicKey", parsed)
	}
	encryptedBytes, err := encryptOAEP(pub, msg)
	if err != nil {
		return nil, errors.Wrap(err, "encryptOAEP")
	}
	encoded := base64.StdEncoding.EncodeToString(encryptedBytes)
	return []byte(encoded), nil
}

func encryptOAEP(key *rsa.PublicKey, msg []byte) ([]byte, error) {
	msgLen := len(msg)
	hash := sha256.New()
	step := key.Size() - 2*hash.Size() - 2
	var encryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}
		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, rand.Reader, key, msg[start:finish], nil)
		if err != nil {
			return nil, errors.Wrap(err, "rsa.EncryptOAEP")
		}
		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}
	return encryptedBytes, nil
}
