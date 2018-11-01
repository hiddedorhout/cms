package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestCreateCMS(t *testing.T) {

	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		Issuer: pkix.Name{
			CommonName: "Hidde Dorhout",
		},
		SerialNumber: big.NewInt(100000000),
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(pkey), pkey)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Errorf("cert: %s", err)
	}

	content := []byte("Hello World")

	cmsBuilder := initCMS(content, false)

	signer := Signer{
		cert: certificate,
		digestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: SHA256OID,
		},
		signatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: DigestAlgorithmSHA256WithRSAOID,
		},
		signedAttributes: []Attribute{},
	}

	if err := cmsBuilder.addSigner(&signer); err != nil {
		t.Fatal(err)
	}

	tbs, err := cmsBuilder.signers[0].createTBS()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, pkey, crypto.SHA256, *tbs)
	if err != nil {
		t.Fatal(err)
	}
	cmsBuilder.signers[0].addSignature(sig)

	cms, err := cmsBuilder.buildCMS()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(base64.StdEncoding.EncodeToString(*cms))
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
