package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type LocksmithAgent struct {
	ls *locksmith.Locksmith
}

func NewLocksmithAgent(ls *locksmith.Locksmith) *LocksmithAgent {
	return &LocksmithAgent{ls: ls}
}

type SSHKeyRecord struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

func getSSHKeysPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".locksmith")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "ssh_keys.json"), nil
}

func LoadSSHKeyRecords() ([]SSHKeyRecord, error) {
	path, err := getSSHKeysPath()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []SSHKeyRecord{}, nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var records []SSHKeyRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func SaveSSHKeyRecords(records []SSHKeyRecord) error {
	path, err := getSSHKeysPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (a *LocksmithAgent) List() ([]*agent.Key, error) {
	records, err := LoadSSHKeyRecords()
	if err != nil {
		return nil, err
	}
	var keys []*agent.Key
	for _, record := range records {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(record.PublicKey))
		if err != nil {
			continue
		}
		keys = append(keys, &agent.Key{
			Format:  pubKey.Type(),
			Blob:    pubKey.Marshal(),
			Comment: record.Name,
		})
	}
	return keys, nil
}

func (a *LocksmithAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	records, err := LoadSSHKeyRecords()
	if err != nil {
		return nil, err
	}

	var matchedName string
	keyMarshal := key.Marshal()
	for _, record := range records {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(record.PublicKey))
		if err != nil {
			continue
		}
		if bytes.Equal(pubKey.Marshal(), keyMarshal) {
			matchedName = record.Name
			break
		}
	}

	if matchedName == "" {
		return nil, fmt.Errorf("key not found in locksmith agent")
	}

	// Fetch private key from Locksmith (triggers biometrics)
	secretName := "ssh/" + matchedName
	privBytes, err := a.ls.Get(secretName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key from keychain: %w", err)
	}
	defer func() {
		for i := range privBytes {
			privBytes[i] = 0
		}
	}()

	privKey, err := ssh.ParseRawPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return signer.Sign(rand.Reader, data)
}

func (a *LocksmithAgent) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			_ = agent.ServeAgent(a, c)
		}(conn)
	}
}

func (a *LocksmithAgent) Add(key agent.AddedKey) error {
	return errors.New("adding keys via ssh-add is disabled for security; use 'locksmith agent add'")
}

func (a *LocksmithAgent) Remove(key ssh.PublicKey) error {
	return errors.New("removing keys via agent is disabled; use 'locksmith delete ssh/<name>'")
}

func (a *LocksmithAgent) RemoveAll() error {
	return errors.New("removing keys via agent is disabled")
}

func (a *LocksmithAgent) Lock(passphrase []byte) error {
	return errors.New("agent locking not supported")
}

func (a *LocksmithAgent) Unlock(passphrase []byte) error {
	return errors.New("agent unlocking not supported")
}

type lazySigner struct {
	agent  *LocksmithAgent
	pubKey ssh.PublicKey
}

func (s *lazySigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s *lazySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.agent.Sign(s.pubKey, data)
}

func (a *LocksmithAgent) Signers() ([]ssh.Signer, error) {
	keys, err := a.List()
	if err != nil {
		return nil, err
	}
	var signers []ssh.Signer
	for _, key := range keys {
		pubKey, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			continue
		}
		signers = append(signers, &lazySigner{
			agent:  a,
			pubKey: pubKey,
		})
	}
	return signers, nil
}
