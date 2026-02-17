// Package cms implements a minimal CMS (Cryptographic Message Syntax) for TSA.
// Based on RFC 5652 (CMS) and RFC 3161 (TSP).
package cms

import "encoding/asn1"

// CMS/PKCS#7 OIDs
var (
	// Content types
	OIDData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDEnvelopedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDAuthEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23} // RFC 5083

	// TSP content type (RFC 3161)
	OIDTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	// Signed attributes
	OIDContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Signing certificate attribute (RFC 5035)
	OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

// Content encryption algorithm OIDs (AES)
var (
	OIDAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OIDAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	OIDAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	OIDAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	OIDAES192GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
	OIDAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
)

// Key wrap algorithm OIDs (RFC 3394)
var (
	OIDAESWrap128 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 5}
	OIDAESWrap192 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 25}
	OIDAESWrap256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 45}
)

// Key transport algorithm OIDs
var (
	OIDRSAES         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1} // PKCS#1 v1.5
	OIDRSAOAEP       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7} // RSA-OAEP
	OIDRSAOAEPSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7} // RSA-OAEP with SHA-256 (params specify hash)
)

// Key agreement algorithm OIDs (ECDH)
var (
	OIDECDHStdSHA1KDF   = asn1.ObjectIdentifier{1, 3, 133, 16, 840, 63, 0, 2} // dhSinglePass-stdDH-sha1kdf-scheme (legacy)
	OIDECDHStdSHA256KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 1}          // dhSinglePass-stdDH-sha256kdf-scheme
	OIDECDHStdSHA384KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 2}          // dhSinglePass-stdDH-sha384kdf-scheme
	OIDECDHStdSHA512KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 3}          // dhSinglePass-stdDH-sha512kdf-scheme
)

// ML-KEM OIDs (FIPS 203)
var (
	OIDMLKEM512  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	OIDMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	OIDMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

// OtherRecipientInfo OIDs (RFC 9629)
var (
	OIDOriKEM = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 13, 3} // id-ori-kem
)

// KDF OIDs
var (
	OIDHKDFSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 28} // id-alg-hkdf-with-sha256
	OIDHKDFSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 29} // id-alg-hkdf-with-sha384
	OIDHKDFSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 30} // id-alg-hkdf-with-sha512
)

// Hash algorithm OIDs
var (
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	OIDSHA3_256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}
	OIDSHA3_384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9}
	OIDSHA3_512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10}

	OIDSHAKE256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 12}
)

// Signature algorithm OIDs
var (
	// ECDSA
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// EdDSA (RFC 8419)
	OIDEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
	OIDEd448   = asn1.ObjectIdentifier{1, 3, 101, 113}

	// RSA
	OIDSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	// ML-DSA (FIPS 204)
	OIDMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	OIDMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OIDMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	// SLH-DSA (FIPS 205, RFC 9814) - SHA2 variants
	OIDSLHDSASHA2128s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}
	OIDSLHDSASHA2128f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}
	OIDSLHDSASHA2192s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}
	OIDSLHDSASHA2192f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}
	OIDSLHDSASHA2256s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24}
	OIDSLHDSASHA2256f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25}

	// SLH-DSA (FIPS 205, RFC 9814) - SHAKE variants
	OIDSLHDSASHAKE128s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26}
	OIDSLHDSASHAKE128f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 27}
	OIDSLHDSASHAKE192s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 28}
	OIDSLHDSASHAKE192f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 29}
	OIDSLHDSASHAKE256s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 30}
	OIDSLHDSASHAKE256f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 31}

	// Backwards compatibility aliases (deprecated)
	OIDSLHDSA128s = OIDSLHDSASHA2128s
	OIDSLHDSA128f = OIDSLHDSASHA2128f
	OIDSLHDSA192s = OIDSLHDSASHA2192s
	OIDSLHDSA192f = OIDSLHDSASHA2192f
	OIDSLHDSA256s = OIDSLHDSASHA2256s
	OIDSLHDSA256f = OIDSLHDSASHA2256f
)
