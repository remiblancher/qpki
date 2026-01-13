package pki.crosstest;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Cross-test: Verify Catalyst Hybrid CRLs with BouncyCastle.
 *
 * Catalyst CRLs (ITU-T X.509 Section 9.8) contain:
 * - Classical signature in signatureValue
 * - PQC signature in AltSignatureValue extension (OID 2.5.29.74)
 * - AltSignatureAlgorithm extension (OID 2.5.29.73)
 *
 * The CA certificate contains:
 * - AltSubjectPublicKeyInfo extension (OID 2.5.29.72) with the PQC public key
 *
 * BouncyCastle 1.78+ supports dual-signature verification via:
 * - isSignatureValid() for classical signature
 * - isAlternativeSignatureValid() for PQC signature
 */
public class CatalystCRLVerifyTest {

    private static final String FIXTURES = "../fixtures/catalyst";

    // ITU-T X.509 (2019) Catalyst OIDs
    private static final ASN1ObjectIdentifier OID_ALT_SIGNATURE_ALGORITHM =
        new ASN1ObjectIdentifier("2.5.29.73");
    private static final ASN1ObjectIdentifier OID_ALT_SIGNATURE_VALUE =
        new ASN1ObjectIdentifier("2.5.29.74");
    private static final ASN1ObjectIdentifier OID_ALT_SUBJECT_PUBLIC_KEY_INFO =
        new ASN1ObjectIdentifier("2.5.29.72");

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @DisplayName("[TC-XBC-CRL-CAT] Verify: Catalyst CRL Classical Signature")
    public void testCrossCompat_Verify_CatalystCRL_ClassicalSignature() throws Exception {
        File crlFile = new File(FIXTURES + "/ca/crl/ca.crl");
        File caFile = new File(FIXTURES + "/ca/ca.crt");

        assumeTrue(crlFile.exists() && caFile.exists(), "Catalyst fixtures not found - run generate_qpki_fixtures.sh");

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509CRLHolder crlHolder = loadCRL(crlFile.getAbsolutePath());

        assertNotNull(crlHolder, "CRL should load");

        // Verify classical signature
        ContentVerifierProvider classicalVerifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue(crlHolder.isSignatureValid(classicalVerifier),
            "Catalyst CRL classical signature should verify");

        System.out.println("Catalyst CRL Classical verification: PASSED");
        System.out.println("  Issuer: " + crlHolder.getIssuer());
        System.out.println("  Primary Algorithm: " + crlHolder.toASN1Structure().getSignatureAlgorithm().getAlgorithm());
    }

    @Test
    @DisplayName("[TC-XBC-CRL-CAT] Verify: Catalyst CRL Alternative (PQC) Signature")
    public void testCrossCompat_Verify_CatalystCRL_AlternativeSignature() throws Exception {
        File crlFile = new File(FIXTURES + "/ca/crl/ca.crl");
        File caFile = new File(FIXTURES + "/ca/ca.crt");

        assumeTrue(crlFile.exists() && caFile.exists(), "Catalyst fixtures not found - run generate_qpki_fixtures.sh");

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509CertificateHolder caHolder = new X509CertificateHolder(caCert.getEncoded());
        X509CRLHolder crlHolder = loadCRL(crlFile.getAbsolutePath());

        assertNotNull(crlHolder, "CRL should load");

        // Get CA's alternative public key from AltSubjectPublicKeyInfo extension
        Extension caAltPubKeyExt = caHolder.getExtension(OID_ALT_SUBJECT_PUBLIC_KEY_INFO);
        assertNotNull(caAltPubKeyExt, "CA should have AltSubjectPublicKeyInfo extension");

        PublicKey altPublicKey = extractAltPublicKey(caAltPubKeyExt);
        assertNotNull(altPublicKey, "Should extract alternative public key");

        // Verify alternative (PQC) signature per ITU-T X.509 Section 9.8
        ContentVerifierProvider altVerifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(altPublicKey);

        assertTrue(crlHolder.isAlternativeSignatureValid(altVerifier),
            "Catalyst CRL alternative (PQC) signature should verify");

        System.out.println("Catalyst CRL Alternative (PQC) verification:");
        System.out.println("  CA Alt Key Algorithm: " + altPublicKey.getAlgorithm());
        System.out.println("  Status: PASSED");
    }

    @Test
    @DisplayName("[TC-XBC-CRL-CAT] Verify: Catalyst CRL Extensions Present")
    public void testCrossCompat_Verify_CatalystCRL_ExtensionsPresent() throws Exception {
        File crlFile = new File(FIXTURES + "/ca/crl/ca.crl");

        assumeTrue(crlFile.exists(), "Catalyst fixtures not found - run generate_qpki_fixtures.sh");

        X509CRLHolder crlHolder = loadCRL(crlFile.getAbsolutePath());

        // Check for Catalyst CRL extensions
        Extension altSigAlg = crlHolder.getExtension(OID_ALT_SIGNATURE_ALGORITHM);
        Extension altSigVal = crlHolder.getExtension(OID_ALT_SIGNATURE_VALUE);

        assertNotNull(altSigAlg, "CRL should have AltSignatureAlgorithm extension (2.5.29.73)");
        assertNotNull(altSigVal, "CRL should have AltSignatureValue extension (2.5.29.74)");

        // Verify extensions are non-critical (for backward compatibility)
        assertFalse(altSigAlg.isCritical(), "AltSignatureAlgorithm should be non-critical");
        assertFalse(altSigVal.isCritical(), "AltSignatureValue should be non-critical");

        System.out.println("Catalyst CRL extensions: VALID");
        System.out.println("  AltSignatureAlgorithm (2.5.29.73): present, non-critical");
        System.out.println("  AltSignatureValue (2.5.29.74): present, non-critical");
    }

    @Test
    @DisplayName("[TC-XBC-CRL-CAT] Verify: Catalyst CRL Both Signatures")
    public void testCrossCompat_Verify_CatalystCRL_BothSignatures() throws Exception {
        File crlFile = new File(FIXTURES + "/ca/crl/ca.crl");
        File caFile = new File(FIXTURES + "/ca/ca.crt");

        assumeTrue(crlFile.exists() && caFile.exists(), "Catalyst fixtures not found - run generate_qpki_fixtures.sh");

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509CertificateHolder caHolder = new X509CertificateHolder(caCert.getEncoded());
        X509CRLHolder crlHolder = loadCRL(crlFile.getAbsolutePath());

        // 1. Verify classical signature
        ContentVerifierProvider classicalVerifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue(crlHolder.isSignatureValid(classicalVerifier),
            "Classical signature should verify");

        // 2. Verify alternative (PQC) signature per ITU-T X.509 Section 9.8
        Extension caAltPubKeyExt = caHolder.getExtension(OID_ALT_SUBJECT_PUBLIC_KEY_INFO);
        assertNotNull(caAltPubKeyExt, "CA should have AltSubjectPublicKeyInfo");

        PublicKey altPublicKey = extractAltPublicKey(caAltPubKeyExt);
        ContentVerifierProvider altVerifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(altPublicKey);

        assertTrue(crlHolder.isAlternativeSignatureValid(altVerifier),
            "Alternative (PQC) signature should verify");

        System.out.println("Catalyst CRL dual-signature verification:");
        System.out.println("  Classical: VERIFIED with " + caCert.getPublicKey().getAlgorithm());
        System.out.println("  Alternative: VERIFIED with " + altPublicKey.getAlgorithm());
    }

    private X509Certificate loadCert(String path) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        try (FileInputStream fis = new FileInputStream(path)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    private X509CRLHolder loadCRL(String path) throws Exception {
        byte[] data = Files.readAllBytes(new File(path).toPath());

        // Try to decode PEM if present
        String content = new String(data);
        if (content.contains("-----BEGIN X509 CRL-----")) {
            String base64 = content
                .replace("-----BEGIN X509 CRL-----", "")
                .replace("-----END X509 CRL-----", "")
                .replaceAll("\\s", "");
            data = java.util.Base64.getDecoder().decode(base64);
        }

        return new X509CRLHolder(data);
    }

    /**
     * Extract the alternative public key from the AltSubjectPublicKeyInfo extension.
     */
    private PublicKey extractAltPublicKey(Extension altPubKeyExt) throws Exception {
        SubjectPublicKeyInfo altSpki = SubjectPublicKeyInfo.getInstance(
            altPubKeyExt.getParsedValue());

        String algorithm = altSpki.getAlgorithm().getAlgorithm().getId();
        KeyFactory keyFactory = KeyFactory.getInstance(
            getAlgorithmName(algorithm), "BC");

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(altSpki.getEncoded());
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Map OID to algorithm name for KeyFactory.
     */
    private String getAlgorithmName(String oid) {
        switch (oid) {
            case "2.16.840.1.101.3.4.3.17": return "ML-DSA-44";
            case "2.16.840.1.101.3.4.3.18": return "ML-DSA-65";
            case "2.16.840.1.101.3.4.3.19": return "ML-DSA-87";
            default: return oid;
        }
    }
}
