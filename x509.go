package rsa

import (
	"crypto/md5"
	"crypto/sha1"
	stdx509 "crypto/x509"
	"encoding/binary"
	"hash"
)

type x509 struct{}

var X509 x509

// Calculates issuer hash value from cert
func (x509) IssuerHash(cert *stdx509.Certificate) (uint32, error) {
	if cert == nil {
		return 0, NilInputError(0)
	}
	return X509.hash(cert.RawIssuer, sha1.New())
}

// Calculates old-style (MD5) issuer hash value from cert
func (x509) IssuerHashOld(cert *stdx509.Certificate) (uint32, error) {
	if cert == nil {
		return 0, NilInputError(0)
	}
	return X509.hash(cert.RawIssuer, md5.New())
}

// Calculates subject hash value from cert
func (x509) SubjectHash(cert *stdx509.Certificate) (uint32, error) {
	if cert == nil {
		return 0, NilInputError(0)
	}
	return X509.hash(cert.RawSubject, sha1.New())
}

// Calculates old-style (MD5) subject hash value from cert
func (x509) SubjectHashOld(cert *stdx509.Certificate) (uint32, error) {
	if cert == nil {
		return 0, NilInputError(0)
	}
	return X509.hash(cert.RawSubject, md5.New())
}

func (x509) hash(b []byte, h hash.Hash) (uint32, error) {
	if b == nil {
		return 0, EmptyInputError(0)
	}
	if h == nil {
		return 0, NilInputError(0)
	}
	if _, err := h.Write(b); err != nil {
		return 0, err
	}
	digest := h.Sum(nil)
	hash := binary.LittleEndian.Uint32(digest[:4])
	return hash, nil
}
