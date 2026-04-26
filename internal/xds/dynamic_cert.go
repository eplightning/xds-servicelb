package xds

import (
	"crypto/tls"
	"sync"
	"time"
)

type DynamicCert struct {
	certPath string
	keyPath  string
	interval time.Duration

	nextRefresh time.Time
	mut         sync.Mutex
	cert        *tls.Certificate
}

func NewDynamicCert(certPath, keyPath string, interval time.Duration) *DynamicCert {
	return &DynamicCert{
		certPath: certPath,
		keyPath:  keyPath,
		interval: interval,
	}
}

func (c *DynamicCert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mut.Lock()
	defer c.mut.Unlock()

	if c.cert == nil || c.nextRefresh.Before(time.Now()) {
		cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
		if err != nil {
			return nil, err
		}

		c.cert = &cert
		c.nextRefresh = time.Now().Add(c.interval)
	}

	return c.cert, nil
}
