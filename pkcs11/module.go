package pkcs11

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/letsencrypt/pkcs11key"
)

func init() {
	caddy.RegisterModule(Module{})
}

type Cert struct {
	// The certificate, in PEM, along with any intermediates.
	CertificatePEM string `json:"certificate"`

	// PKCS11 module
	PoolSize   int    `json:"pool_size"`
	ModulePath string `json:"module_path"`
	TokenLabel string `json:"token_label"`
	PIN        string `json:"pin"`

	// The PKCS11 key pool
	keyPool *pkcs11key.Pool
}

type Module []Cert

func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificates.pkcs11",
		New: func() caddy.Module { return new(Module) },
	}
}

// Interface guards
var _ caddytls.CertificateLoader = (Module)(nil)
var _ caddy.CleanerUpper = (Module)(nil)

// loadPEMCerts finds all certificates in a file, decoding all the PEM blocks.
func loadPEMCerts(data []byte) [][]byte {
	for {
		var certs [][]byte
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return certs
		}
		// Ignore any other data in the PEM files that aren't the certificates.
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
	}
}

func (m Module) LoadCertificates() ([]caddytls.Certificate, error) {
	var ret []caddytls.Certificate

	for _, c := range m {
		certs := loadPEMCerts([]byte(c.CertificatePEM))

		leaf, err := x509.ParseCertificate(certs[0])
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %v", err)
		}

		pool, err := pkcs11key.NewPool(c.PoolSize, c.ModulePath, c.TokenLabel, c.PIN, leaf.PublicKey)
		if err != nil {
			return nil, err
		}
		c.keyPool = pool

		ret = append(ret, caddytls.Certificate{
			Certificate: tls.Certificate{
				Certificate: certs,
				PrivateKey:  pool,
				Leaf:        leaf,
			},
			Tags: nil,
		})
	}

	return ret, nil
}

func (m Module) Cleanup() error {
	var errors []error
	for _, c := range m {
		if c.keyPool != nil {
			err := c.keyPool.Destroy()
			if err != nil {
				errors = append(errors, err)
			}
		}
	}

	switch len(errors) {
	case 0:
		return nil
	case 1:
		return errors[0]
	default:
		return fmt.Errorf("errors cleaning up keypools: %v", errors)
	}
}
