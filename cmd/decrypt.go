package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var (
	decryptKeyFile    string
	decryptInputFile  string
	decryptOutputFile string
)

func init() {
	decryptCmd.Flags().StringVarP(&decryptKeyFile, "key", "k", "", "key file")
	decryptCmd.Flags().StringVarP(&decryptInputFile, "input", "i", "", "input file to encrypt")
	decryptCmd.Flags().StringVarP(&decryptOutputFile, "output", "o", "", "output file to write data")
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "decrypt a file using a private key",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if decryptKeyFile == "" {
			homeDir, err := homedir.Dir()
			if err != nil {
				return errors.Wrap(err, "homedir.Dir")
			}
			decryptKeyFile = filepath.Join(homeDir, "/.ssh/id_rsa")
		}
		if decryptInputFile == "" {
			return errors.New("missing input file")
		}
		if decryptOutputFile == "" {
			return errors.New("missing output file")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		bs, err := os.ReadFile(decryptInputFile)
		if err != nil {
			return errors.Wrap(err, "os.ReadFile")
		}
		decrypted, err := decrypt(bs, decryptKeyFile)
		if err != nil {
			return errors.Wrap(err, "decrypt")
		}
		f, err := os.Create(decryptOutputFile)
		if err != nil {
			return errors.Wrap(err, "os.Create")
		}
		defer f.Close()
		_, err = f.Write(decrypted)
		return errors.Wrap(err, "f.Write")
	},
}

func decrypt(msg []byte, keyFile string) ([]byte, error) {
	bs, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, errors.Wrap(err, "os.ReadFile")
	}
	block, _ := pem.Decode(bs)
	if block == nil {
		return nil, errors.New("pem.Decode: no key found")
	}
	keyInterface, err := ssh.ParseRawPrivateKey(bs)
	if err != nil {
		return nil, errors.Wrap(err, "ssh.ParseRawPrivateKey")
	}
	key, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.Errorf("ssh.ParseRawPrivateKey: not rsa key: is: %T", keyInterface)
	}
	data, err := base64.StdEncoding.DecodeString(string(msg))
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString")
	}
	decryptedBytes, err := decryptOAEP(key, data)
	if err != nil {
		return nil, errors.Wrap(err, "decryptOAEP")
	}
	return decryptedBytes, nil
}

func decryptOAEP(private *rsa.PrivateKey, msg []byte) ([]byte, error) {
	msgLen := len(msg)
	hash := sha256.New()
	step := private.PublicKey.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, rand.Reader, private, msg[start:finish], nil)
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
}
