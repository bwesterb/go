package x509_test

import (
	cryptoRand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	kemSchemes "github.com/cloudflare/circl/kem/schemes"
	sigSchemes "github.com/cloudflare/circl/sign/schemes"
	"golang.org/x/crypto/sha3"
)

func testCreatePQKEMExample(t *testing.T, sigName, kemName string) {
	sigScheme := sigSchemes.ByName(sigName)
	kemScheme := kemSchemes.ByName(kemName)
	var sigSeed [32]byte // 000102…1e1f
	var kemSeed [64]byte // 000102…3e3f

	for i := 0; i < len(sigSeed); i++ {
		sigSeed[i] = byte(i)
	}
	for i := 0; i < len(kemSeed); i++ {
		kemSeed[i] = byte(i)
	}

	sigPk, sigSk := sigScheme.DeriveKey(sigSeed[:])
	kemPk, _ := kemScheme.DeriveKeyPair(kemSeed[:])

	sigPpk, _ := sigPk.MarshalBinary()
	kemPpk, _ := kemPk.MarshalBinary()
	var sigSki, kemSki [20]byte
	sha3.ShakeSum256(sigSki[:], sigPpk)
	sha3.ShakeSum256(kemSki[:], kemPpk)

	sigSerialNumber := new(big.Int)
	kemSerialNumber := new(big.Int)
	sigSerialNumber.SetString("123456789012345678901234567890123456789012345678", 10)
	kemSerialNumber.SetString("123456789012345678901234567890123456789012345679", 10)
	notBefore := time.Date(2020, time.February, 3, 4, 32, 10, 12, time.UTC)
	notAfter := notBefore.Add(20 * 365 * 24 * time.Hour)

	sigTemplate := &x509.Certificate{
		SerialNumber: sigSerialNumber,
		Subject: pkix.Name{
			Organization: []string{"IETF"},
			CommonName:   "LAMPS WG",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          sigSki[:],
		IsCA:                  true,
	}
	kemTemplate := &x509.Certificate{
		SerialNumber: kemSerialNumber,
		Subject: pkix.Name{
			Organization: []string{"IETF"},
			CommonName:   "LAMPS WG",
		},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageKeyEncipherment,
		SubjectKeyId:   kemSki[:],
		AuthorityKeyId: sigSki[:],
	}

	cert, err := x509.CreateCertificate(cryptoRand.Reader, kemTemplate, sigTemplate,
		kemPk, sigSk)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(fmt.Sprintf("%s.pem", kemName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		t.Fatal(err)
	}
}

func testCreatePQSigExample(t *testing.T, name string) {
	scheme := sigSchemes.ByName(name)
	var seed [32]byte // 000102…1e1f

	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i)
	}

	pk, sk := scheme.DeriveKey(seed[:])

	serialNumber := new(big.Int)
	serialNumber.SetString("123456789012345678901234567890123456789012345678", 10)
	notBefore := time.Date(2020, time.February, 3, 4, 32, 10, 12, time.UTC)
	notAfter := notBefore.Add(20 * 365 * 24 * time.Hour)
	ppk, _ := pk.MarshalBinary()
	var ski [20]byte
	sha3.ShakeSum256(ski[:], ppk)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"IETF"},
			CommonName:   "LAMPS WG",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          ski[:],
		IsCA:                  true,
	}

	cert, err := x509.CreateCertificate(cryptoRand.Reader, template, template,
		pk, sk)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(fmt.Sprintf("%s.pem", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		t.Fatal(err)
	}
}

func TestCreatePQExamples(t *testing.T) {
	testCreatePQSigExample(t, "ML-DSA-44")
	testCreatePQSigExample(t, "ML-DSA-65")
	testCreatePQSigExample(t, "ML-DSA-87")
	testCreatePQKEMExample(t, "ML-DSA-44", "ML-KEM-512")
	testCreatePQKEMExample(t, "ML-DSA-65", "ML-KEM-768")
	testCreatePQKEMExample(t, "ML-DSA-87", "ML-KEM-1024")
}
