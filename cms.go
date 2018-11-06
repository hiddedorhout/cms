package cms

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"time"
)

var (
	// DataOID is the ASN.1 type ContentInfo for arbitrary octet strings
	DataOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	//SignedDataOID identifies the signed-data content type
	SignedDataOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	// SHA256OID identifies the SHA256 digest
	SHA256OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	// SHA1OID identifies the SHA1 digest
	SHA1OID = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	// AttributeContentTypeOID identifies Content Type
	AttributeContentTypeOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	// AttributeSigningTimeOID identifies Signing Time Attribute
	AttributeSigningTimeOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	// AttributeMessageDigestOID identifies the message digest attribute
	AttributeMessageDigestOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	// DigestAlgorithmSHA256WithRSAOID identifies the rsa sha256 signing algorithm
	DigestAlgorithmSHA256WithRSAOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	// DigestAlgorithmSHA1WithRSAOID identifies the rsa sha1 signing algorithm
	DigestAlgorithmSHA1WithRSAOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
)

// ContentInfo encapsulates the content type and the content of the CMS.
// The CMS associates a content type identifier with a content.
// The syntax MUST have ASN.1 type ContentInfo
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// EncapsulatedContentInfo represents the content
type EncapsulatedContentInfo struct {
	EcontentType asn1.ObjectIdentifier
	Econtent     []byte `asn1:"explicit,optional,tag:0"`
}

// SignedData type consists of a content of any type and
// zero or more signature values.  Any number of signers in parallel can
// sign any type of content.
type SignedData struct {
	Version          int                        `ans1:"default:1"`
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo    `asn1:"sequence"`
	Certificates     rawCertificates            `asn1:"implicit,optional,tag:0"`
	Crls             []pkix.CertificateList     `asn1:"implicit,optional,tag:1"`
	SignerInfos      []SignerInfo               `asn1:"set"`
}

type rawCertificates struct {
	Certs asn1.RawContent
}

// Attribute represents a key value pair. Value must be an ASN.1 marshalable octet string
type Attribute struct {
	AttrType   asn1.ObjectIdentifier
	AttrValues interface{} `asn1:"set"`
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// SignerInfo is a collection of per-signer information
type SignerInfo struct {
	Version            int `asn1:"default:1"`
	Sid                issuerAndSerialNumber
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttributes   []Attribute `asn1:"optional,tag:0,set"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes []Attribute `asn1:"optional,tag:1"`
}

// Builder is a type used to support the building of a CMS
type Builder struct {
	data         []byte
	signers      map[string]*Signer
	dataDetached bool
}

// Signer is a type to describe a signer
type Signer struct {
	Cert               *x509.Certificate
	CRLs               *pkix.CertificateList
	DigestAlgorithm    pkix.AlgorithmIdentifier
	ContentDigest      []byte
	SignedAttributes   []Attribute
	UnsignedAttributes []Attribute
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

// InitCMS initializes a CMS builder
func InitCMS(content []byte, detached bool) *Builder {
	return &Builder{
		data:         content,
		dataDetached: detached,
		signers:      make(map[string]*Signer),
	}
}

// NewSigner adds a signer to the CMS and returns a signerID, which can be used to create a to be signed byte array and add a signature
func (cmsbuilder *Builder) NewSigner(
	cert interface{},
	crls *pkix.CertificateList,
	digestAlgorithm crypto.Hash,
	signedAttributes []Attribute,
) (signerID *string, err error) {

	var signer Signer

	switch c := cert.(type) {
	case *x509.Certificate:
		signer.Cert = c
	default:
		return nil, errors.New("Unsupported Certificate type")
	}

	if crls != nil {
		signer.CRLs = crls
	}

	switch digestAlgorithm {
	case crypto.SHA256:
		signer.DigestAlgorithm = pkix.AlgorithmIdentifier{
			Algorithm: SHA256OID,
			Parameters: asn1.RawValue{
				IsCompound: true,
				Tag:        5,
			},
		}
		signer.SignatureAlgorithm = pkix.AlgorithmIdentifier{
			Algorithm: DigestAlgorithmSHA256WithRSAOID,
			Parameters: asn1.RawValue{
				IsCompound: true,
				Tag:        5,
			},
		}
	case crypto.SHA1:
		signer.DigestAlgorithm = pkix.AlgorithmIdentifier{
			Algorithm: SHA1OID,
			Parameters: asn1.RawValue{
				IsCompound: true,
				Tag:        5,
			},
		}
		signer.SignatureAlgorithm = pkix.AlgorithmIdentifier{
			Algorithm: DigestAlgorithmSHA1WithRSAOID,
			Parameters: asn1.RawValue{
				IsCompound: true,
				Tag:        5,
			},
		}
	default:
		return nil, errors.New("Only SHA1 and SHA256 Supported")
	}

	signer.SignedAttributes = signedAttributes

	signerid, err := cmsbuilder.addSigner(&signer)
	if err != nil {
		return nil, err
	}

	return signerid, nil

}

// CreateTBS creates a To Be Signed byte array to sign for a signer
func (cmsbuilder *Builder) CreateTBS(signerID string) (tbs *[]byte, err error) {

	signer := cmsbuilder.signers[signerID]

	attributes := []Attribute{
		Attribute{
			AttrType:   AttributeSigningTimeOID,
			AttrValues: time.Now(),
		},
		Attribute{
			AttrType:   AttributeContentTypeOID,
			AttrValues: SignedDataOID,
		},
		Attribute{
			AttrType:   AttributeMessageDigestOID,
			AttrValues: signer.ContentDigest,
		},
	}

	for _, attr := range signer.SignedAttributes {
		attributes = append(attributes, attr)
	}

	derAttrs, err := marshalAttributes(attributes)
	if err != nil {
		return nil, err
	}

	signer.SignedAttributes = derAttrs

	mAttributes, err := asn1.Marshal(derAttrs)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write(mAttributes)
	hash := h.Sum(nil)

	return &hash, nil
}

// AddSignature adds the created signature for a signer and possible unsigned attributes
func (cmsbuilder *Builder) AddSignature(signerID string, signature []byte, unsignedAttributes []Attribute) error {

	signer := cmsbuilder.signers[signerID]
	if signer == nil {
		return errors.New("No signer found")
	}

	if len(unsignedAttributes) != 0 {
		unsignedAttrs, err := marshalAttributes(unsignedAttributes)
		if err != nil {
			return err
		}

		signer.UnsignedAttributes = unsignedAttrs
	}

	signer.Signature = signature
	signer.SignatureAlgorithm = pkix.AlgorithmIdentifier{
		Algorithm: DigestAlgorithmSHA256WithRSAOID,
	}
	return nil
}

// Build creates the CMS
func (cmsbuilder *Builder) Build() (cms *[]byte, err error) {
	sd := SignedData{}
	sd.Version = 1

	switch cmsbuilder.dataDetached {
	case true:
		sd.EncapContentInfo = EncapsulatedContentInfo{
			EcontentType: SignedDataOID,
			Econtent:     nil,
		}
	case false:
		sd.EncapContentInfo = EncapsulatedContentInfo{
			EcontentType: SignedDataOID,
			Econtent:     cmsbuilder.data,
		}
	}

	var certBuffer bytes.Buffer

	for _, signer := range cmsbuilder.signers {
		sd.DigestAlgorithms = append(sd.DigestAlgorithms, signer.DigestAlgorithm)
		certBuffer.Write(signer.Cert.Raw)
		si := SignerInfo{
			Version: 1,
			Sid: issuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: signer.Cert.RawIssuer},
				SerialNumber: signer.Cert.SerialNumber,
			},
			DigestAlgorithm:    signer.DigestAlgorithm,
			SignedAttributes:   signer.SignedAttributes,
			SignatureAlgorithm: signer.SignatureAlgorithm,
			Signature:          signer.Signature,
			UnsignedAttributes: signer.UnsignedAttributes,
		}
		sd.SignerInfos = append(sd.SignerInfos, si)
	}

	c, err := asn1.Marshal(asn1.RawValue{
		Class:      2,
		Tag:        0,
		Bytes:      certBuffer.Bytes(),
		IsCompound: true,
	})
	if err != nil {
		return nil, err
	}

	sd.Certificates = rawCertificates{
		Certs: c,
	}

	inner, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}

	ci := ContentInfo{
		ContentType: SignedDataOID,
		Content: asn1.RawValue{
			Tag:        0,
			Class:      2,
			Bytes:      inner,
			IsCompound: true,
		},
	}
	result, err := asn1.Marshal(ci)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (cmsbuilder *Builder) addSigner(signer *Signer) (signerID *string, err error) {

	h := sha256.New()
	h.Write(cmsbuilder.data)
	digest := h.Sum(nil)
	signer.ContentDigest = digest

	signerIdentifier := base64.StdEncoding.EncodeToString(signer.Cert.Raw)

	cmsbuilder.signers[signerIdentifier] = signer

	return &signerIdentifier, nil
}

func marshalAttributes(attributes []Attribute) (derEncodedAttr []Attribute, err error) {
	encodedAttr := make([]Attribute, len(attributes))
	for i, attribute := range attributes {
		der, err := asn1.Marshal(attribute.AttrValues)
		if err != nil {
			return nil, err
		}
		attr := Attribute{
			AttrType: attribute.AttrType,
			AttrValues: asn1.RawValue{
				Tag:        17,
				IsCompound: true,
				Bytes:      der,
			},
		}
		encodedAttr[i] = attr
	}
	return encodedAttr, nil
}

// Values is a type to unmarshal cms
type Values struct {
	contentType asn1.ObjectIdentifier
	eContent    EncapsulatedContentInfo
	certs       []*x509.Certificate
	crls        []*pkix.CertificateList
	signerInfos map[*big.Int]*SignerInfo
}

type signedData struct {
	Version          int                        `ans1:"default:1"`
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo    `asn1:"sequence"`
	Certificates     rawCertificates            `asn1:"implicit,optional,tag:0"`
	Crls             []pkix.CertificateList     `asn1:"implicit,optional,tag:1"`
	SignerInfos      []signerInfo               `asn1:"set"`
}

// Attribute represents a key value pair. Value must be an ASN.1 marshalable octet string
type attribute struct {
	AttrType   asn1.ObjectIdentifier
	AttrValues asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version            int `asn1:"default:1"`
	Sid                issuerAndSerialNumber
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttributes   []attribute `asn1:"optional,tag:0,set"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes []attribute `asn1:"optional,tag:1"`
}

// ParseCMS takes a raw CMS and parses it to a CMS object
func ParseCMS(rawCMS []byte) (cms *Values, err error) {
	var contentInfo ContentInfo
	if _, err := asn1.Unmarshal(rawCMS, &contentInfo); err != nil {
		return nil, err
	}

	var sd signedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &sd); err != nil {
		return nil, err
	}
	CMS := Values{
		contentType: contentInfo.ContentType,
		eContent:    sd.EncapContentInfo,
		signerInfos: make(map[*big.Int]*SignerInfo),
	}

	certs, err := parseCerts(sd.Certificates.Certs)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		CMS.certs = append(CMS.certs, c)
	}

	for _, sI := range sd.SignerInfos {

		SI := SignerInfo{
			Version:            sI.Version,
			Sid:                sI.Sid,
			DigestAlgorithm:    sI.DigestAlgorithm,
			SignedAttributes:   make([]Attribute, 0),
			SignatureAlgorithm: sI.SignatureAlgorithm,
			Signature:          sI.Signature,
			UnsignedAttributes: make([]Attribute, 0),
		}

		for _, attr := range sI.SignedAttributes {
			var rawAttr interface{}
			if _, err := asn1.Unmarshal(attr.AttrValues.Bytes, &rawAttr); err != nil {
				return nil, err
			}
			SI.SignedAttributes = append(SI.SignedAttributes, Attribute{
				AttrType:   attr.AttrType,
				AttrValues: rawAttr,
			})
		}

		for _, attr := range sI.UnsignedAttributes {
			var rawAttr interface{}
			if _, err := asn1.Unmarshal(attr.AttrValues.Bytes, &rawAttr); err != nil {
				return nil, err
			}
			SI.UnsignedAttributes = append(SI.UnsignedAttributes, Attribute{
				AttrType:   attr.AttrType,
				AttrValues: rawAttr,
			})
		}
		CMS.signerInfos[SI.Sid.SerialNumber] = &SI
	}

	return &CMS, nil
}

func parseCerts(certs asn1.RawContent) (certificates []*x509.Certificate, err error) {

	var c asn1.RawValue
	if _, err := asn1.Unmarshal(certs, &c); err != nil {
		return nil, err
	}
	crts, err := x509.ParseCertificates(c.Bytes)
	if err != nil {
		return nil, err
	}
	return crts, nil
}
