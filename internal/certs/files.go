package certs

import "os"

func (id Identity) Save(certPath, keyPath string) error {
	if err := os.WriteFile(certPath, id.Cert, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, id.Key, 0o600)
}

func Load(certPath, keyPath string) (Identity, error) {
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return Identity{}, err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Cert: cert, Key: key}, nil
}

func LoadPair(caFile, certFile, keyFile string) (id, ca Identity, err error) {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return Identity{}, Identity{}, err
	}
	ca = Identity{Cert: caCert}
	id, err = Load(certFile, keyFile)
	if err != nil {
		return Identity{}, Identity{}, err
	}
	return id, ca, nil
}
