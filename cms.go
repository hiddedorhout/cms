package cms

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	// DataOID is the ASN.1 type ContentInfo for arbitrary octet strings
	DataOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	//SignedDataOID identifies the signed-data content type
	SignedDataOID                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	SHA256OID                       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	AttributeContentTypeOID         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	AttributeSigningTimeOID         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	AttributeMessageDigestOID       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	DigestAlgorithmSHA256WithRSAOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
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
	Certificates     []asn1.RawContent          `asn1:"implicit,set,optional,tag:0"`
	// Crls             interface{}                `asn1:"optional,tag:1"`
	SignerInfos []asn1.RawValue `asn1:"set"`
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

type CMSbuilder struct {
	data         []byte
	signers      []*Signer
	dataDetached bool
}

type Signer struct {
	cert               *x509.Certificate
	digestAlgorithm    pkix.AlgorithmIdentifier
	contentDigest      []byte
	signedAttributes   []Attribute
	unsignedAttributes []Attribute
	signatureAlgorithm pkix.AlgorithmIdentifier
	signature          []byte
}

func initCMS(content []byte, detached bool) *CMSbuilder {
	return &CMSbuilder{
		data:         content,
		dataDetached: detached,
	}
}

func (cmsbuilder *CMSbuilder) addSigner(signer *Signer) error {
	if signer.digestAlgorithm.Algorithm.Equal(SHA256OID) {
		h := sha256.New()
		h.Write(cmsbuilder.data)
		digest := h.Sum(nil)
		signer.contentDigest = digest

		cmsbuilder.signers = append(cmsbuilder.signers, signer)
		return nil
	}
	return errors.New("Unsupported digest algorithm (only sha2 at the moment")
}

func (signer *Signer) createTBS() (tbs *[]byte, err error) {
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
			AttrValues: signer.contentDigest,
		},
	}

	for _, attr := range signer.signedAttributes {
		attributes = append(attributes, attr)
	}

	derAttrs, err := marshalAttributes(attributes)
	if err != nil {
		return nil, err
	}

	signer.signedAttributes = derAttrs

	mAttributes, err := asn1.Marshal(derAttrs)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write(mAttributes)
	hash := h.Sum(nil)

	return &hash, nil
}

func (signer *Signer) addSignature(signature []byte) error {
	signer.signature = signature
	signer.signatureAlgorithm = pkix.AlgorithmIdentifier{
		Algorithm: DigestAlgorithmSHA256WithRSAOID,
	}
	return nil
}

func (cmsbuilder *CMSbuilder) buildCMS() (cms *[]byte, err error) {
	sd := SignedData{}
	sd.Version = 1
	sd.EncapContentInfo = EncapsulatedContentInfo{
		EcontentType: SignedDataOID,
		Econtent:     cmsbuilder.data,
	}

	for _, signer := range cmsbuilder.signers {
		sd.DigestAlgorithms = append(sd.DigestAlgorithms, signer.digestAlgorithm)
		sd.Certificates = append(sd.Certificates, signer.cert.Raw)
		si := SignerInfo{
			Version: 1,
			Sid: issuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: signer.cert.RawIssuer},
				SerialNumber: signer.cert.SerialNumber,
			},
			DigestAlgorithm:    signer.digestAlgorithm,
			SignedAttributes:   signer.signedAttributes,
			SignatureAlgorithm: signer.signatureAlgorithm,
			Signature:          signer.signature,
			UnsignedAttributes: signer.unsignedAttributes,
		}
		dersi, err := asn1.Marshal(si)
		if err != nil {
			return nil, err
		}
		sd.SignerInfos = append(sd.SignerInfos, asn1.RawValue{
			Tag:        16,
			IsCompound: true,
			Bytes:      dersi,
		})
	}

	fmt.Printf("%+v", sd)
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
