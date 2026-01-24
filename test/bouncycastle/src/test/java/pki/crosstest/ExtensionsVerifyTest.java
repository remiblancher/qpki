package pki.crosstest;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;

import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * RFC 5280 Extension Compliance Tests with BouncyCastle.
 *
 * Verifies X.509 extension encoding and conformance:
 * - Basic Constraints (criticality, CA flag, pathLen)
 * - Key Usage (criticality, bit values)
 * - Extended Key Usage (OID values)
 * - Certificate Policies (CPS URI as IA5String - bug fix verification)
 * - Subject Alternative Name (GeneralNames encoding)
 * - CRL Distribution Points (DistributionPoint encoding)
 * - Authority Information Access (AccessDescription encoding)
 * - Name Constraints (permitted/excluded subtrees)
 * - Subject/Authority Key Identifiers
 */
public class ExtensionsVerifyTest {

    private static final String FIXTURES = "../fixtures";

    // RFC 5280 Extension OIDs
    private static final ASN1ObjectIdentifier OID_BASIC_CONSTRAINTS = Extension.basicConstraints;
    private static final ASN1ObjectIdentifier OID_KEY_USAGE = Extension.keyUsage;
    private static final ASN1ObjectIdentifier OID_EXT_KEY_USAGE = Extension.extendedKeyUsage;
    private static final ASN1ObjectIdentifier OID_CERT_POLICIES = Extension.certificatePolicies;
    private static final ASN1ObjectIdentifier OID_SUBJECT_ALT_NAME = Extension.subjectAlternativeName;
    private static final ASN1ObjectIdentifier OID_CRL_DIST_POINTS = Extension.cRLDistributionPoints;
    private static final ASN1ObjectIdentifier OID_AUTH_INFO_ACCESS = Extension.authorityInfoAccess;
    private static final ASN1ObjectIdentifier OID_NAME_CONSTRAINTS = Extension.nameConstraints;
    private static final ASN1ObjectIdentifier OID_SUBJECT_KEY_ID = Extension.subjectKeyIdentifier;
    private static final ASN1ObjectIdentifier OID_AUTHORITY_KEY_ID = Extension.authorityKeyIdentifier;

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // =========================================================================
    // Certificate Policies Tests (CPS URI IA5String fix verification)
    // =========================================================================

    @Nested
    @DisplayName("Certificate Policies Extension")
    class CertificatePoliciesTests {

        @Test
        @DisplayName("[RFC5280] CPS URI must be IA5String not PrintableString")
        void certificatePolicies_cpsURI_isIA5String() throws Exception {
            // Test with classical CA that has certificate policies
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ecdsa/ca/ca.crt");

            Extension ext = cert.getExtension(OID_CERT_POLICIES);
            if (ext == null) {
                System.out.println("SKIP: Classical CA has no certificatePolicies extension");
                return;
            }

            // Parse the extension
            CertificatePolicies policies = CertificatePolicies.getInstance(ext.getParsedValue());
            assertNotNull(policies, "Should parse CertificatePolicies");

            for (PolicyInformation pi : policies.getPolicyInformation()) {
                ASN1Sequence qualifiers = pi.getPolicyQualifiers();
                if (qualifiers == null) continue;

                for (int i = 0; i < qualifiers.size(); i++) {
                    PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(qualifiers.getObjectAt(i));

                    // Check if this is a CPS qualifier
                    if (PolicyQualifierId.id_qt_cps.equals(pqi.getPolicyQualifierId())) {
                        ASN1Encodable qualifier = pqi.getQualifier();

                        // CPS URI MUST be IA5String per RFC 5280 Section 4.2.1.4
                        // This test catches the bug where PrintableString was used
                        assertTrue(qualifier instanceof DERIA5String || qualifier instanceof ASN1IA5String,
                            "CPS URI must be IA5String, got: " + qualifier.getClass().getSimpleName());

                        String uri = ((ASN1String) qualifier).getString();
                        System.out.println("CPS URI (IA5String): " + uri);
                        assertTrue(uri.startsWith("http"), "CPS URI should be a valid URL");
                    }
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] Certificate Policies is non-critical")
        void certificatePolicies_isNonCritical() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ecdsa/ca/ca.crt");

            Extension ext = cert.getExtension(OID_CERT_POLICIES);
            if (ext == null) {
                System.out.println("SKIP: No certificatePolicies extension");
                return;
            }

            // Certificate Policies SHOULD NOT be critical for interoperability
            assertFalse(ext.isCritical(),
                "Certificate Policies should not be critical (RFC 5280 4.2.1.4)");
        }
    }

    // =========================================================================
    // Basic Constraints Tests
    // =========================================================================

    @Nested
    @DisplayName("Basic Constraints Extension")
    class BasicConstraintsTests {

        @Test
        @DisplayName("[RFC5280] CA certificate has BasicConstraints critical=true, CA=true")
        void basicConstraints_CA_isCriticalAndTrue() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ecdsa/ca/ca.crt");

            Extension ext = cert.getExtension(OID_BASIC_CONSTRAINTS);
            assertNotNull(ext, "CA must have BasicConstraints");
            assertTrue(ext.isCritical(), "BasicConstraints MUST be critical for CA (RFC 5280 4.2.1.9)");

            BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
            assertTrue(bc.isCA(), "CA certificate must have CA=true");

            System.out.println("BasicConstraints: CA=" + bc.isCA() +
                ", pathLen=" + bc.getPathLenConstraint());
        }

        @Test
        @DisplayName("[RFC5280] End-entity certificate has no CA constraint")
        void basicConstraints_EE_notCA() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_BASIC_CONSTRAINTS);

            if (ext != null) {
                BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
                assertFalse(bc.isCA(), "End-entity must not have CA=true");
            }
            // If no BasicConstraints, that's also valid for EE
        }

        @Test
        @DisplayName("[RFC5280] PathLength encoding is correct")
        void basicConstraints_pathLength_encoding() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ecdsa/ca/ca.crt");

            Extension ext = cert.getExtension(OID_BASIC_CONSTRAINTS);
            if (ext == null) return;

            BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
            BigInteger pathLen = bc.getPathLenConstraint();

            if (pathLen != null) {
                assertTrue(pathLen.intValue() >= 0, "PathLen must be non-negative");
                System.out.println("PathLen constraint: " + pathLen);
            }
        }
    }

    // =========================================================================
    // Key Usage Tests
    // =========================================================================

    @Nested
    @DisplayName("Key Usage Extension")
    class KeyUsageTests {

        @Test
        @DisplayName("[RFC5280] Key Usage is critical for CA")
        void keyUsage_CA_isCritical() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ecdsa/ca/ca.crt");

            Extension ext = cert.getExtension(OID_KEY_USAGE);
            assertNotNull(ext, "CA should have KeyUsage");
            assertTrue(ext.isCritical(), "KeyUsage MUST be critical (RFC 5280 4.2.1.3)");
        }

        @Test
        @DisplayName("[RFC5280] CA has keyCertSign and cRLSign")
        void keyUsage_CA_hasCorrectBits() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ecdsa/ca/ca.crt");

            Extension ext = cert.getExtension(OID_KEY_USAGE);
            if (ext == null) {
                System.out.println("SKIP: No KeyUsage extension");
                return;
            }

            KeyUsage ku = KeyUsage.getInstance(ext.getParsedValue());

            // CA must have keyCertSign (bit 5)
            assertTrue(ku.hasUsages(KeyUsage.keyCertSign),
                "CA must have keyCertSign");
            assertTrue(ku.hasUsages(KeyUsage.cRLSign),
                "CA should have cRLSign");

            System.out.println("CA KeyUsage: keyCertSign=" + ku.hasUsages(KeyUsage.keyCertSign) +
                ", cRLSign=" + ku.hasUsages(KeyUsage.cRLSign));
        }

        @Test
        @DisplayName("[RFC5280] All Key Usage bits parse correctly")
        void keyUsage_allBits_parseCorrectly() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_KEY_USAGE);

            if (ext != null) {
                KeyUsage ku = KeyUsage.getInstance(ext.getParsedValue());

                // Print all key usage bits
                StringBuilder sb = new StringBuilder("EE KeyUsage:");
                if (ku.hasUsages(KeyUsage.digitalSignature)) sb.append(" digitalSignature");
                if (ku.hasUsages(KeyUsage.nonRepudiation)) sb.append(" nonRepudiation");
                if (ku.hasUsages(KeyUsage.keyEncipherment)) sb.append(" keyEncipherment");
                if (ku.hasUsages(KeyUsage.dataEncipherment)) sb.append(" dataEncipherment");
                if (ku.hasUsages(KeyUsage.keyAgreement)) sb.append(" keyAgreement");
                if (ku.hasUsages(KeyUsage.keyCertSign)) sb.append(" keyCertSign");
                if (ku.hasUsages(KeyUsage.cRLSign)) sb.append(" cRLSign");
                if (ku.hasUsages(KeyUsage.encipherOnly)) sb.append(" encipherOnly");
                if (ku.hasUsages(KeyUsage.decipherOnly)) sb.append(" decipherOnly");

                System.out.println(sb);
            }
        }
    }

    // =========================================================================
    // Subject Alternative Name Tests
    // =========================================================================

    @Nested
    @DisplayName("Subject Alternative Name Extension")
    class SubjectAltNameTests {

        @Test
        @DisplayName("[RFC5280] DNS names are IA5String")
        void subjectAltName_dnsNames_areIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);

            if (ext == null) {
                System.out.println("SKIP: No SAN extension");
                return;
            }

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.dNSName) {
                    ASN1Encodable name = gn.getName();
                    // DNS names must be IA5String
                    assertTrue(name instanceof DERIA5String || name instanceof ASN1IA5String,
                        "DNS name must be IA5String");
                    System.out.println("DNS name (IA5String): " + ((ASN1String) name).getString());
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] Email addresses are IA5String")
        void subjectAltName_email_isIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);
            if (ext == null) return;

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.rfc822Name) {
                    ASN1Encodable name = gn.getName();
                    assertTrue(name instanceof DERIA5String || name instanceof ASN1IA5String,
                        "Email must be IA5String");
                    System.out.println("Email (IA5String): " + ((ASN1String) name).getString());
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] IP addresses are OCTET STRING")
        void subjectAltName_ipAddress_isOctetString() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);
            if (ext == null) return;

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.iPAddress) {
                    ASN1Encodable addr = gn.getName();
                    assertTrue(addr instanceof ASN1OctetString,
                        "IP address must be OCTET STRING");
                    byte[] bytes = ((ASN1OctetString) addr).getOctets();
                    assertTrue(bytes.length == 4 || bytes.length == 16,
                        "IP must be 4 (IPv4) or 16 (IPv6) bytes");
                    System.out.println("IP address: " + formatIP(bytes));
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] URIs are IA5String")
        void subjectAltName_uri_isIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);
            if (ext == null) return;

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    ASN1Encodable uri = gn.getName();
                    assertTrue(uri instanceof DERIA5String || uri instanceof ASN1IA5String,
                        "URI must be IA5String");
                    System.out.println("URI (IA5String): " + ((ASN1String) uri).getString());
                }
            }
        }
    }

    // =========================================================================
    // CRL Distribution Points Tests
    // =========================================================================

    @Nested
    @DisplayName("CRL Distribution Points Extension")
    class CRLDistributionPointsTests {

        @Test
        @DisplayName("[RFC5280] CRL DP URIs are IA5String")
        void crlDistPoints_uri_isIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_CRL_DIST_POINTS);

            if (ext == null) {
                System.out.println("SKIP: No CRLDP extension");
                return;
            }

            CRLDistPoint cdp = CRLDistPoint.getInstance(ext.getParsedValue());
            for (DistributionPoint dp : cdp.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralNames names = GeneralNames.getInstance(dpn.getName());
                    for (GeneralName gn : names.getNames()) {
                        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            ASN1Encodable uri = gn.getName();
                            assertTrue(uri instanceof DERIA5String || uri instanceof ASN1IA5String,
                                "CRL DP URI must be IA5String");
                            System.out.println("CRL DP URI (IA5String): " + ((ASN1String) uri).getString());
                        }
                    }
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] CRL Distribution Points is non-critical")
        void crlDistPoints_isNonCritical() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) return;

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_CRL_DIST_POINTS);

            if (ext != null) {
                assertFalse(ext.isCritical(),
                    "CRLDP should not be critical (RFC 5280 4.2.1.13)");
            }
        }
    }

    // =========================================================================
    // Authority Information Access Tests
    // =========================================================================

    @Nested
    @DisplayName("Authority Information Access Extension")
    class AuthorityInfoAccessTests {

        @Test
        @DisplayName("[RFC5280] AIA MUST NOT be critical")
        void authorityInfoAccess_isNotCritical() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) return;

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_AUTH_INFO_ACCESS);

            if (ext != null) {
                assertFalse(ext.isCritical(),
                    "AIA MUST NOT be critical (RFC 5280 4.2.2.1)");
            }
        }

        @Test
        @DisplayName("[RFC5280] OCSP URI is IA5String")
        void authorityInfoAccess_ocsp_isIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_AUTH_INFO_ACCESS);

            if (ext == null) {
                System.out.println("SKIP: No AIA extension");
                return;
            }

            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ext.getParsedValue());
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_ocsp.equals(ad.getAccessMethod())) {
                    GeneralName location = ad.getAccessLocation();
                    if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        ASN1Encodable uri = location.getName();
                        assertTrue(uri instanceof DERIA5String || uri instanceof ASN1IA5String,
                            "OCSP URI must be IA5String");
                        System.out.println("OCSP URI (IA5String): " + ((ASN1String) uri).getString());
                    }
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] CA Issuers URI is IA5String")
        void authorityInfoAccess_caIssuers_isIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) return;

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_AUTH_INFO_ACCESS);
            if (ext == null) return;

            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ext.getParsedValue());
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_caIssuers.equals(ad.getAccessMethod())) {
                    GeneralName location = ad.getAccessLocation();
                    if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        ASN1Encodable uri = location.getName();
                        assertTrue(uri instanceof DERIA5String || uri instanceof ASN1IA5String,
                            "CA Issuers URI must be IA5String");
                        System.out.println("CA Issuers URI (IA5String): " + ((ASN1String) uri).getString());
                    }
                }
            }
        }
    }

    // =========================================================================
    // Extended Key Usage Tests
    // =========================================================================

    @Nested
    @DisplayName("Extended Key Usage Extension")
    class ExtendedKeyUsageTests {

        @Test
        @DisplayName("[RFC5280] EKU OIDs parse correctly")
        void extKeyUsage_oidsParseCorrectly() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_EXT_KEY_USAGE);

            if (ext == null) {
                System.out.println("SKIP: No EKU extension");
                return;
            }

            ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ext.getParsedValue());
            KeyPurposeId[] purposes = eku.getUsages();

            System.out.println("Extended Key Usage OIDs:");
            for (KeyPurposeId kp : purposes) {
                System.out.println("  - " + kp.getId() + " (" + getEKUName(kp) + ")");
            }

            assertTrue(purposes.length > 0, "EKU should have at least one purpose");
        }

        private String getEKUName(KeyPurposeId kp) {
            if (KeyPurposeId.id_kp_serverAuth.equals(kp)) return "serverAuth";
            if (KeyPurposeId.id_kp_clientAuth.equals(kp)) return "clientAuth";
            if (KeyPurposeId.id_kp_codeSigning.equals(kp)) return "codeSigning";
            if (KeyPurposeId.id_kp_emailProtection.equals(kp)) return "emailProtection";
            if (KeyPurposeId.id_kp_timeStamping.equals(kp)) return "timeStamping";
            if (KeyPurposeId.id_kp_OCSPSigning.equals(kp)) return "OCSPSigning";
            return "unknown";
        }
    }

    // =========================================================================
    // Subject/Authority Key Identifier Tests
    // =========================================================================

    @Nested
    @DisplayName("Key Identifier Extensions")
    class KeyIdentifierTests {

        @Test
        @DisplayName("[RFC5280] Subject Key Identifier is non-critical")
        void subjectKeyIdentifier_isNonCritical() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ecdsa/ca/ca.crt");

            Extension ext = cert.getExtension(OID_SUBJECT_KEY_ID);
            assertNotNull(ext, "CA should have SKI");
            assertFalse(ext.isCritical(), "SKI MUST NOT be critical (RFC 5280 4.2.1.2)");

            SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(ext.getParsedValue());
            assertNotNull(ski.getKeyIdentifier(), "SKI should have value");
            System.out.println("SKI length: " + ski.getKeyIdentifier().length + " bytes");
        }

        @Test
        @DisplayName("[RFC5280] Authority Key Identifier is non-critical")
        void authorityKeyIdentifier_isNonCritical() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ecdsa/credentials");
            if (eePath == null) return;

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_AUTHORITY_KEY_ID);

            if (ext != null) {
                assertFalse(ext.isCritical(), "AKI MUST NOT be critical (RFC 5280 4.2.1.1)");

                AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(ext.getParsedValue());
                if (aki.getKeyIdentifier() != null) {
                    System.out.println("AKI length: " + aki.getKeyIdentifier().length + " bytes");
                }
            }
        }
    }

    // =========================================================================
    // Name Constraints Tests
    // =========================================================================

    @Nested
    @DisplayName("Name Constraints Extension")
    class NameConstraintsTests {

        @Test
        @DisplayName("[RFC5280] Name Constraints should be critical")
        void nameConstraints_shouldBeCritical() throws Exception {
            // Most fixtures won't have name constraints, but if they do, verify
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ecdsa/ca/ca.crt");

            Extension ext = cert.getExtension(OID_NAME_CONSTRAINTS);
            if (ext == null) {
                System.out.println("INFO: No nameConstraints (optional for CA)");
                return;
            }

            assertTrue(ext.isCritical(),
                "nameConstraints SHOULD be critical (RFC 5280 4.2.1.10)");

            org.bouncycastle.asn1.x509.NameConstraints nc =
                org.bouncycastle.asn1.x509.NameConstraints.getInstance(ext.getParsedValue());

            if (nc.getPermittedSubtrees() != null) {
                System.out.println("Permitted subtrees: " + nc.getPermittedSubtrees().length);
            }
            if (nc.getExcludedSubtrees() != null) {
                System.out.println("Excluded subtrees: " + nc.getExcludedSubtrees().length);
            }
        }
    }

    // =========================================================================
    // PQC Certificate Extension Tests
    // =========================================================================

    @Nested
    @DisplayName("PQC Certificate Extensions")
    class PQCExtensionTests {

        @Test
        @DisplayName("[PQC] ML-DSA CA has correct extensions")
        void mldsa_CA_hasCorrectExtensions() throws Exception {
            File caFile = new File(FIXTURES + "/pqc/mldsa/ca/ca.crt");
            assumeTrue(caFile.exists(), "ML-DSA fixtures not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(caFile.getPath());

            // Basic Constraints
            Extension bc = cert.getExtension(OID_BASIC_CONSTRAINTS);
            assertNotNull(bc, "ML-DSA CA must have BasicConstraints");
            assertTrue(bc.isCritical(), "BasicConstraints must be critical");
            assertTrue(BasicConstraints.getInstance(bc.getParsedValue()).isCA());

            // Key Usage
            Extension ku = cert.getExtension(OID_KEY_USAGE);
            assertNotNull(ku, "ML-DSA CA must have KeyUsage");
            assertTrue(ku.isCritical(), "KeyUsage must be critical");

            System.out.println("ML-DSA CA extensions verified");
        }

        @Test
        @DisplayName("[PQC] Catalyst hybrid CA has correct extensions")
        void catalyst_CA_hasCorrectExtensions() throws Exception {
            File caFile = new File(FIXTURES + "/catalyst/ca/ca.crt");
            assumeTrue(caFile.exists(), "Catalyst fixtures not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(caFile.getPath());

            // Basic Constraints
            Extension bc = cert.getExtension(OID_BASIC_CONSTRAINTS);
            assertNotNull(bc, "Catalyst CA must have BasicConstraints");
            assertTrue(bc.isCritical(), "BasicConstraints must be critical");

            // Key Usage
            Extension ku = cert.getExtension(OID_KEY_USAGE);
            assertNotNull(ku, "Catalyst CA must have KeyUsage");
            assertTrue(ku.isCritical(), "KeyUsage must be critical");

            System.out.println("Catalyst CA extensions verified");
        }
    }

    // =========================================================================
    // Extension Variant Cross-Tests (using generated fixtures)
    // =========================================================================

    @Nested
    @DisplayName("Extension Variant Cross-Tests")
    class ExtensionVariantTests {

        private static final String VARIANT_FIXTURES = "../fixtures/extension-variants";

        // --- CertificatePolicies Variants ---

        @Test
        @DisplayName("[Variant] ext-cp-cps: CPS URI parsed correctly")
        void extCpCps_cpsUriParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-cp-cps.crt");
            assumeTrue(certFile.exists(), "ext-cp-cps.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_CERT_POLICIES);
            assertNotNull(ext, "Should have CertificatePolicies extension");

            CertificatePolicies policies = CertificatePolicies.getInstance(ext.getParsedValue());
            boolean foundCps = false;
            for (PolicyInformation pi : policies.getPolicyInformation()) {
                ASN1Sequence qualifiers = pi.getPolicyQualifiers();
                if (qualifiers == null) continue;
                for (int i = 0; i < qualifiers.size(); i++) {
                    PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(qualifiers.getObjectAt(i));
                    if (PolicyQualifierId.id_qt_cps.equals(pqi.getPolicyQualifierId())) {
                        ASN1Encodable qualifier = pqi.getQualifier();
                        assertTrue(qualifier instanceof DERIA5String || qualifier instanceof ASN1IA5String,
                            "CPS URI must be IA5String");
                        foundCps = true;
                    }
                }
            }
            assertTrue(foundCps, "Should find CPS qualifier");
        }

        @Test
        @DisplayName("[Variant] ext-cp-notice: UserNotice parsed correctly")
        void extCpNotice_userNoticeParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-cp-notice.crt");
            assumeTrue(certFile.exists(), "ext-cp-notice.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_CERT_POLICIES);
            assertNotNull(ext, "Should have CertificatePolicies extension");

            CertificatePolicies policies = CertificatePolicies.getInstance(ext.getParsedValue());
            boolean foundNotice = false;
            for (PolicyInformation pi : policies.getPolicyInformation()) {
                ASN1Sequence qualifiers = pi.getPolicyQualifiers();
                if (qualifiers == null) continue;
                for (int i = 0; i < qualifiers.size(); i++) {
                    PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(qualifiers.getObjectAt(i));
                    if (PolicyQualifierId.id_qt_unotice.equals(pqi.getPolicyQualifierId())) {
                        foundNotice = true;
                    }
                }
            }
            assertTrue(foundNotice, "Should find UserNotice qualifier");
        }

        @Test
        @DisplayName("[Variant] ext-cp-both: CPS and UserNotice parsed correctly")
        void extCpBoth_bothParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-cp-both.crt");
            assumeTrue(certFile.exists(), "ext-cp-both.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_CERT_POLICIES);
            assertNotNull(ext, "Should have CertificatePolicies extension");

            CertificatePolicies policies = CertificatePolicies.getInstance(ext.getParsedValue());
            boolean foundCps = false;
            boolean foundNotice = false;
            for (PolicyInformation pi : policies.getPolicyInformation()) {
                ASN1Sequence qualifiers = pi.getPolicyQualifiers();
                if (qualifiers == null) continue;
                for (int i = 0; i < qualifiers.size(); i++) {
                    PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(qualifiers.getObjectAt(i));
                    if (PolicyQualifierId.id_qt_cps.equals(pqi.getPolicyQualifierId())) {
                        foundCps = true;
                    }
                    if (PolicyQualifierId.id_qt_unotice.equals(pqi.getPolicyQualifierId())) {
                        foundNotice = true;
                    }
                }
            }
            assertTrue(foundCps, "Should find CPS qualifier");
            assertTrue(foundNotice, "Should find UserNotice qualifier");
        }

        // --- SubjectAltName Variants ---

        @Test
        @DisplayName("[Variant] ext-san-dns: DNS names parsed correctly")
        void extSanDns_dnsParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-san-dns.crt");
            assumeTrue(certFile.exists(), "ext-san-dns.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);
            assertNotNull(ext, "Should have SAN extension");

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            boolean foundDns = false;
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.dNSName) {
                    ASN1Encodable name = gn.getName();
                    assertTrue(name instanceof DERIA5String || name instanceof ASN1IA5String,
                        "DNS name must be IA5String");
                    foundDns = true;
                }
            }
            assertTrue(foundDns, "Should find DNS names");
        }

        @Test
        @DisplayName("[Variant] ext-san-email: Email addresses parsed correctly")
        void extSanEmail_emailParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-san-email.crt");
            assumeTrue(certFile.exists(), "ext-san-email.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);
            assertNotNull(ext, "Should have SAN extension");

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            boolean foundEmail = false;
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.rfc822Name) {
                    ASN1Encodable name = gn.getName();
                    assertTrue(name instanceof DERIA5String || name instanceof ASN1IA5String,
                        "Email must be IA5String");
                    foundEmail = true;
                }
            }
            assertTrue(foundEmail, "Should find email addresses");
        }

        @Test
        @DisplayName("[Variant] ext-san-uri: URIs parsed correctly")
        void extSanUri_uriParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-san-uri.crt");
            assumeTrue(certFile.exists(), "ext-san-uri.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);
            assertNotNull(ext, "Should have SAN extension");

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            boolean foundUri = false;
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    ASN1Encodable uri = gn.getName();
                    assertTrue(uri instanceof DERIA5String || uri instanceof ASN1IA5String,
                        "URI must be IA5String");
                    foundUri = true;
                }
            }
            assertTrue(foundUri, "Should find URIs");
        }

        @Test
        @DisplayName("[Variant] ext-san-ip: IPv4 and IPv6 addresses parsed correctly")
        void extSanIp_ipParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-san-ip.crt");
            assumeTrue(certFile.exists(), "ext-san-ip.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);
            assertNotNull(ext, "Should have SAN extension");

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            boolean foundIpv4 = false;
            boolean foundIpv6 = false;
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.iPAddress) {
                    ASN1Encodable addr = gn.getName();
                    assertTrue(addr instanceof ASN1OctetString, "IP must be OCTET STRING");
                    byte[] bytes = ((ASN1OctetString) addr).getOctets();
                    if (bytes.length == 4) foundIpv4 = true;
                    if (bytes.length == 16) foundIpv6 = true;
                }
            }
            assertTrue(foundIpv4, "Should find IPv4 address");
            assertTrue(foundIpv6, "Should find IPv6 address");
        }

        @Test
        @DisplayName("[Variant] ext-san-all: All SAN types parsed correctly")
        void extSanAll_allTypesParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-san-all.crt");
            assumeTrue(certFile.exists(), "ext-san-all.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);
            assertNotNull(ext, "Should have SAN extension");

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            boolean foundDns = false, foundEmail = false, foundUri = false, foundIp = false;
            for (GeneralName gn : san.getNames()) {
                switch (gn.getTagNo()) {
                    case GeneralName.dNSName: foundDns = true; break;
                    case GeneralName.rfc822Name: foundEmail = true; break;
                    case GeneralName.uniformResourceIdentifier: foundUri = true; break;
                    case GeneralName.iPAddress: foundIp = true; break;
                }
            }
            assertTrue(foundDns, "Should find DNS");
            assertTrue(foundEmail, "Should find email");
            assertTrue(foundUri, "Should find URI");
            assertTrue(foundIp, "Should find IP");
        }

        // --- BasicConstraints Variants ---

        @Test
        @DisplayName("[Variant] ext-bc-ca: CA:TRUE parsed correctly")
        void extBcCa_caTrueParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-bc-ca.crt");
            assumeTrue(certFile.exists(), "ext-bc-ca.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_BASIC_CONSTRAINTS);
            assertNotNull(ext, "Should have BasicConstraints extension");
            assertTrue(ext.isCritical(), "BasicConstraints must be critical");

            BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
            assertTrue(bc.isCA(), "Should be CA:TRUE");
        }

        @Test
        @DisplayName("[Variant] ext-bc-ca-pathlen: CA:TRUE with pathLen parsed correctly")
        void extBcCaPathlen_pathlenParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-bc-ca-pathlen.crt");
            assumeTrue(certFile.exists(), "ext-bc-ca-pathlen.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_BASIC_CONSTRAINTS);
            assertNotNull(ext, "Should have BasicConstraints extension");

            BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
            assertTrue(bc.isCA(), "Should be CA:TRUE");
            assertNotNull(bc.getPathLenConstraint(), "Should have pathLen");
        }

        // --- KeyUsage Variants ---

        @Test
        @DisplayName("[Variant] ext-ku-ca: CA KeyUsage parsed correctly")
        void extKuCa_caKeyUsageParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-ku-ca.crt");
            assumeTrue(certFile.exists(), "ext-ku-ca.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_KEY_USAGE);
            assertNotNull(ext, "Should have KeyUsage extension");
            assertTrue(ext.isCritical(), "KeyUsage must be critical");

            KeyUsage ku = KeyUsage.getInstance(ext.getParsedValue());
            assertTrue(ku.hasUsages(KeyUsage.keyCertSign), "Should have keyCertSign");
            assertTrue(ku.hasUsages(KeyUsage.cRLSign), "Should have cRLSign");
        }

        // --- ExtendedKeyUsage Variants ---

        @Test
        @DisplayName("[Variant] ext-eku-tls: TLS Server Auth parsed correctly")
        void extEkuTls_tlsAuthParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-eku-tls.crt");
            assumeTrue(certFile.exists(), "ext-eku-tls.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_EXT_KEY_USAGE);
            assertNotNull(ext, "Should have ExtKeyUsage extension");

            ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ext.getParsedValue());
            assertTrue(eku.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth),
                "Should have serverAuth");
        }

        @Test
        @DisplayName("[Variant] ext-eku-code: Code Signing parsed correctly")
        void extEkuCode_codeSigningParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-eku-code.crt");
            assumeTrue(certFile.exists(), "ext-eku-code.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_EXT_KEY_USAGE);
            assertNotNull(ext, "Should have ExtKeyUsage extension");

            ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ext.getParsedValue());
            assertTrue(eku.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning),
                "Should have codeSigning");
        }

        @Test
        @DisplayName("[Variant] ext-eku-ocsp: OCSP Signing parsed correctly")
        void extEkuOcsp_ocspSigningParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-eku-ocsp.crt");
            assumeTrue(certFile.exists(), "ext-eku-ocsp.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_EXT_KEY_USAGE);
            assertNotNull(ext, "Should have ExtKeyUsage extension");

            ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ext.getParsedValue());
            assertTrue(eku.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning),
                "Should have OCSPSigning");
        }

        @Test
        @DisplayName("[Variant] ext-eku-tsa: Time Stamping parsed correctly")
        void extEkuTsa_timeStampingParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-eku-tsa.crt");
            assumeTrue(certFile.exists(), "ext-eku-tsa.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_EXT_KEY_USAGE);
            assertNotNull(ext, "Should have ExtKeyUsage extension");

            ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ext.getParsedValue());
            assertTrue(eku.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping),
                "Should have timeStamping");
        }

        // --- CRLDistributionPoints Variants ---

        @Test
        @DisplayName("[Variant] ext-crldp-http: CRL DP URI parsed correctly")
        void extCrldpHttp_uriParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-crldp-http.crt");
            assumeTrue(certFile.exists(), "ext-crldp-http.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_CRL_DIST_POINTS);
            assertNotNull(ext, "Should have CRLDP extension");

            CRLDistPoint cdp = CRLDistPoint.getInstance(ext.getParsedValue());
            boolean foundUri = false;
            for (DistributionPoint dp : cdp.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralNames names = GeneralNames.getInstance(dpn.getName());
                    for (GeneralName gn : names.getNames()) {
                        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            foundUri = true;
                        }
                    }
                }
            }
            assertTrue(foundUri, "Should find CRL DP URI");
        }

        @Test
        @DisplayName("[Variant] ext-crldp-multi: Multiple CRL DPs parsed correctly")
        void extCrldpMulti_multipleUrisParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-crldp-multi.crt");
            assumeTrue(certFile.exists(), "ext-crldp-multi.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_CRL_DIST_POINTS);
            assertNotNull(ext, "Should have CRLDP extension");

            CRLDistPoint cdp = CRLDistPoint.getInstance(ext.getParsedValue());
            int uriCount = 0;
            for (DistributionPoint dp : cdp.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralNames names = GeneralNames.getInstance(dpn.getName());
                    for (GeneralName gn : names.getNames()) {
                        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            uriCount++;
                        }
                    }
                }
            }
            assertTrue(uriCount >= 2, "Should have multiple CRL DP URIs, found: " + uriCount);
        }

        // --- AuthorityInfoAccess Variants ---

        @Test
        @DisplayName("[Variant] ext-aia-ocsp: OCSP responder URI parsed correctly")
        void extAiaOcsp_ocspParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-aia-ocsp.crt");
            assumeTrue(certFile.exists(), "ext-aia-ocsp.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_AUTH_INFO_ACCESS);
            assertNotNull(ext, "Should have AIA extension");
            assertFalse(ext.isCritical(), "AIA must not be critical");

            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ext.getParsedValue());
            boolean foundOcsp = false;
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_ocsp.equals(ad.getAccessMethod())) {
                    foundOcsp = true;
                }
            }
            assertTrue(foundOcsp, "Should find OCSP responder");
        }

        @Test
        @DisplayName("[Variant] ext-aia-ca: CA Issuers URI parsed correctly")
        void extAiaCa_caIssuersParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-aia-ca.crt");
            assumeTrue(certFile.exists(), "ext-aia-ca.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_AUTH_INFO_ACCESS);
            assertNotNull(ext, "Should have AIA extension");

            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ext.getParsedValue());
            boolean foundCaIssuers = false;
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_caIssuers.equals(ad.getAccessMethod())) {
                    foundCaIssuers = true;
                }
            }
            assertTrue(foundCaIssuers, "Should find CA Issuers");
        }

        @Test
        @DisplayName("[Variant] ext-aia-both: OCSP and CA Issuers parsed correctly")
        void extAiaBoth_bothParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-aia-both.crt");
            assumeTrue(certFile.exists(), "ext-aia-both.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_AUTH_INFO_ACCESS);
            assertNotNull(ext, "Should have AIA extension");

            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ext.getParsedValue());
            boolean foundOcsp = false;
            boolean foundCaIssuers = false;
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_ocsp.equals(ad.getAccessMethod())) {
                    foundOcsp = true;
                }
                if (AccessDescription.id_ad_caIssuers.equals(ad.getAccessMethod())) {
                    foundCaIssuers = true;
                }
            }
            assertTrue(foundOcsp, "Should find OCSP");
            assertTrue(foundCaIssuers, "Should find CA Issuers");
        }

        // --- NameConstraints Variants ---

        @Test
        @DisplayName("[Variant] ext-nc-permit: Permitted subtrees parsed correctly")
        void extNcPermit_permittedParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-nc-permit.crt");
            assumeTrue(certFile.exists(), "ext-nc-permit.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_NAME_CONSTRAINTS);
            assertNotNull(ext, "Should have NameConstraints extension");
            assertTrue(ext.isCritical(), "NameConstraints should be critical");

            org.bouncycastle.asn1.x509.NameConstraints nc =
                org.bouncycastle.asn1.x509.NameConstraints.getInstance(ext.getParsedValue());
            assertNotNull(nc.getPermittedSubtrees(), "Should have permitted subtrees");
            assertTrue(nc.getPermittedSubtrees().length > 0, "Should have at least one permitted subtree");
        }

        @Test
        @DisplayName("[Variant] ext-nc-exclude: Excluded subtrees parsed correctly")
        void extNcExclude_excludedParsed() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-nc-exclude.crt");
            assumeTrue(certFile.exists(), "ext-nc-exclude.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_NAME_CONSTRAINTS);
            assertNotNull(ext, "Should have NameConstraints extension");
            assertTrue(ext.isCritical(), "NameConstraints should be critical");

            org.bouncycastle.asn1.x509.NameConstraints nc =
                org.bouncycastle.asn1.x509.NameConstraints.getInstance(ext.getParsedValue());
            assertNotNull(nc.getExcludedSubtrees(), "Should have excluded subtrees");
            assertTrue(nc.getExcludedSubtrees().length > 0, "Should have at least one excluded subtree");
        }

        // --- Criticality Configuration Tests ---

        @Test
        @DisplayName("[Variant] ext-eku-critical: EKU is critical when configured")
        void extEkuCritical_isCritical() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-eku-critical.crt");
            assumeTrue(certFile.exists(), "ext-eku-critical.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_EXT_KEY_USAGE);
            assertNotNull(ext, "Should have ExtKeyUsage extension");
            assertTrue(ext.isCritical(), "EKU should be critical when configured as critical");
        }

        @Test
        @DisplayName("[Variant] ext-eku-noncritical: EKU is non-critical when configured")
        void extEkuNoncritical_isNotCritical() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-eku-noncritical.crt");
            assumeTrue(certFile.exists(), "ext-eku-noncritical.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_EXT_KEY_USAGE);
            assertNotNull(ext, "Should have ExtKeyUsage extension");
            assertFalse(ext.isCritical(), "EKU should be non-critical when configured as non-critical");
        }

        @Test
        @DisplayName("[Variant] ext-cp-critical: CertPolicies is critical when configured")
        void extCpCritical_isCritical() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-cp-critical.crt");
            assumeTrue(certFile.exists(), "ext-cp-critical.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_CERT_POLICIES);
            assertNotNull(ext, "Should have CertificatePolicies extension");
            assertTrue(ext.isCritical(), "CertPolicies should be critical when configured as critical");
        }

        @Test
        @DisplayName("[Variant] ext-cp-noncritical: CertPolicies is non-critical when configured")
        void extCpNoncritical_isNotCritical() throws Exception {
            File certFile = new File(VARIANT_FIXTURES + "/ext-cp-noncritical.crt");
            assumeTrue(certFile.exists(), "ext-cp-noncritical.crt not found - run generate_qpki_fixtures.sh");

            X509CertificateHolder cert = loadCertHolder(certFile.getPath());
            Extension ext = cert.getExtension(OID_CERT_POLICIES);
            assertNotNull(ext, "Should have CertificatePolicies extension");
            assertFalse(ext.isCritical(), "CertPolicies should be non-critical when configured as non-critical");
        }
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    private X509CertificateHolder loadCertHolder(String path) throws Exception {
        File file = new File(path);
        if (!file.exists()) {
            throw new RuntimeException("Certificate file not found: " + path);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        try (FileInputStream fis = new FileInputStream(file)) {
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            return new X509CertificateHolder(cert.getEncoded());
        }
    }

    private String findCredentialCert(String credentialsDir) {
        File dir = new File(credentialsDir);
        if (!dir.exists() || !dir.isDirectory()) {
            return null;
        }

        File[] subdirs = dir.listFiles(File::isDirectory);
        if (subdirs == null || subdirs.length == 0) {
            return null;
        }

        File certFile = new File(subdirs[0], "certificates.pem");
        if (certFile.exists()) {
            return certFile.getAbsolutePath();
        }
        return null;
    }

    private String formatIP(byte[] bytes) {
        if (bytes.length == 4) {
            return String.format("%d.%d.%d.%d",
                bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF, bytes[3] & 0xFF);
        }
        // IPv6
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i += 2) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x%02x", bytes[i] & 0xFF, bytes[i + 1] & 0xFF));
        }
        return sb.toString();
    }
}
