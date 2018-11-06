package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestCreateCMS(t *testing.T) {

	// A private key and self signed certificate are generated to sign the CMS

	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(64), nil).Sub(max, big.NewInt(1))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "John Doe",
		},
		SerialNumber: n,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(pkey), pkey)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Errorf("cert: %s", err)
	}

	// Random content as data

	content := []byte("Hello World")

	cmsBuilder := InitCMS(content, false)

	signerID, err := cmsBuilder.NewSigner(certificate, nil, crypto.SHA256, []Attribute{
		Attribute{
			AttrType:   asn1.ObjectIdentifier{0, 0, 0, 0, 1}, // a random oid
			AttrValues: "example signed attribute",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := cmsBuilder.CreateTBS(*signerID)
	if err != nil {
		t.Fatal(err)
	}

	// Sign the To Be Signed string
	sig, err := rsa.SignPKCS1v15(rand.Reader, pkey, crypto.SHA256, *tbs)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmsBuilder.AddSignature(*signerID, sig, []Attribute{
		Attribute{
			AttrType:   asn1.ObjectIdentifier{0, 0, 0, 0, 2}, // a random oid
			AttrValues: "example unsigned attribute",
		},
	}); err != nil {
		t.Fatal(err)
	}

	cms, err := cmsBuilder.Build()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseCMS(*cms); err != nil {
		t.Fatal(err)
	}
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
