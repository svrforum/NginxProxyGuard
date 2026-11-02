package nginx

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

// certLacksOCSPResponder reports whether the leaf certificate of a fullchain
// names no OCSP responder. Let's Encrypt stopped putting one in its
// certificates in 2025, and with ssl_stapling on nginx warns about every such
// certificate on each reload and test (#359), so the server blocks that use
// one switch stapling off. A file that cannot be read or parsed is not
// reported: nginx keeps deciding about it as before.
func certLacksOCSPResponder(fullchain string) bool {
	rest, err := os.ReadFile(fullchain)
	if err != nil {
		return false
	}
	for {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return false
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		return err == nil && len(cert.OCSPServer) == 0
	}
}
