// Package certs generates a private CA and issues the certificates components use for mutual TLS.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type Identity struct {
	Cert []byte
	Key  []byte
}

func serial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func NewCA() (Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	sn, err := serial()
	if err != nil {
		return Identity{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "tessera CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return Identity{}, err
	}
	return encode(der, key)
}

func Issue(ca Identity, commonName, dnsName string) (Identity, error) {
	caCert, caKey, err := parse(ca)
	if err != nil {
		return Identity{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	sn, err := serial()
	if err != nil {
		return Identity{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return Identity{}, err
	}
	return encode(der, key)
}

func encode(der []byte, key *ecdsa.PrivateKey) (Identity, error) {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func parse(id Identity) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode(id.Cert)
	kb, _ := pem.Decode(id.Key)
	if cb == nil || kb == nil {
		return nil, nil, fmt.Errorf("certs: malformed PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func pool(ca Identity) (*x509.CertPool, error) {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(ca.Cert) {
		return nil, fmt.Errorf("certs: bad CA cert")
	}
	return p, nil
}

func ServerTLS(id, ca Identity) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(id.Cert, id.Key)
	if err != nil {
		return nil, err
	}
	p, err := pool(ca)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func ClientTLS(id, ca Identity, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(id.Cert, id.Key)
	if err != nil {
		return nil, err
	}
	p, err := pool(ca)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      p,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
