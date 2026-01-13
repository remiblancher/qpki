package pki.crosstest;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cross-test: Verify Catalyst Hybrid certificates with BouncyCastle.
 *
 * Catalyst certificates (ITU-T X.509 Section 9.8) contain:
 * - Classical signature in signatureValue
 * - PQC signature in AltSignatureValue extension (OID 2.5.29.74)
 * - PQC public key in AltSubjectPublicKeyInfo extension (OID 2.5.29.72)
 *
 * BouncyCastle 1.78+ supports dual-signature verification via:
 * - isSignatureValid() for classical signature
 * - isAlternativeSignatureValid() for PQC signature (X.509 Section 9.8)
 */
public class CatalystVerifyTest {

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
    @DisplayName("[TC-XBC-CERT-CAT] Verify: Catalyst CA Both Signatures")
    public void testCrossCompat_Verify_CatalystCABothSignatures() throws Exception {
        File caFile = new File(FIXTURES + "/ca/ca.crt");
        if (!caFile.exists()) {
            System.out.println("Catalyst fixtures not found, skipping test");
            return;
        }

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        assertNotNull(caCert, "Catalyst CA certificate should load");

        X509CertificateHolder holder = new X509CertificateHolder(caCert.getEncoded());

        // 1. Verify classical signature
        ContentVerifierProvider classicalVerifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue(holder.isSignatureValid(classicalVerifier),
            "Catalyst CA classical signature should verify");
        System.out.println("Catalyst CA Classical verification: PASSED");

        // 2. Verify alternative (PQC) signature
        Extension altPubKeyExt = holder.getExtension(OID_ALT_SUBJECT_PUBLIC_KEY_INFO);
        assertNotNull(altPubKeyExt, "Catalyst cert should have AltSubjectPublicKeyInfo");

        // Extract PQC public key from extension
        PublicKey altPublicKey = extractAltPublicKey(altPubKeyExt);
        assertNotNull(altPublicKey, "Should extract alternative public key");

        ContentVerifierProvider altVerifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(altPublicKey);

        assertTrue(holder.isAlternativeSignatureValid(altVerifier),
            "Catalyst CA alternative (PQC) signature should verify");
        System.out.println("Catalyst CA Alternative (PQC) verification: PASSED");

        // Check all Catalyst extensions present
        boolean hasAltSigAlg = holder.getExtension(OID_ALT_SIGNATURE_ALGORITHM) != null;
        boolean hasAltSigVal = holder.getExtension(OID_ALT_SIGNATURE_VALUE) != null;

        System.out.println("  Algorithm: " + altPublicKey.getAlgorithm());
        System.out.println("  AltSignatureAlgorithm (2.5.29.73): " + hasAltSigAlg);
        System.out.println("  AltSignatureValue (2.5.29.74): " + hasAltSigVal);
        System.out.println("  AltSubjectPublicKeyInfo (2.5.29.72): true");

        assertTrue(hasAltSigAlg, "Catalyst cert should have AltSignatureAlgorithm");
        assertTrue(hasAltSigVal, "Catalyst cert should have AltSignatureValue");
    }

    @Test
    @DisplayName("[TC-XBC-CERT-CAT] Verify: Catalyst End-Entity Both Signatures")
    public void testCrossCompat_Verify_CatalystEndEntityBothSignatures() throws Exception {
        File caFile = new File(FIXTURES + "/ca/ca.crt");
        if (!caFile.exists()) {
            System.out.println("Catalyst fixtures not found, skipping test");
            return;
        }

        String eeCertPath = findCredentialCert(FIXTURES + "/ca/credentials");
        if (eeCertPath == null) {
            System.out.println("No Catalyst credential certificate found, skipping EE test");
            return;
        }

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509Certificate eeCert = loadCert(eeCertPath);

        X509CertificateHolder caHolder = new X509CertificateHolder(caCert.getEncoded());
        X509CertificateHolder eeHolder = new X509CertificateHolder(eeCert.getEncoded());

        // 1. Verify classical signature against CA
        ContentVerifierProvider classicalVerifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue(eeHolder.isSignatureValid(classicalVerifier),
            "Catalyst EE classical signature should verify");
        System.out.println("Catalyst EE Classical verification: PASSED");

        // 2. Verify alternative (PQC) signature against CA's alt public key
        Extension caAltPubKeyExt = caHolder.getExtension(OID_ALT_SUBJECT_PUBLIC_KEY_INFO);
        assertNotNull(caAltPubKeyExt, "CA should have AltSubjectPublicKeyInfo");

        PublicKey caAltPublicKey = extractAltPublicKey(caAltPubKeyExt);
        assertNotNull(caAltPublicKey, "Should extract CA alternative public key");

        ContentVerifierProvider altVerifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caAltPublicKey);

        assertTrue(eeHolder.isAlternativeSignatureValid(altVerifier),
            "Catalyst EE alternative (PQC) signature should verify");
        System.out.println("Catalyst EE Alternative (PQC) verification: PASSED");

        System.out.println("  Subject: " + eeCert.getSubjectX500Principal());
        System.out.println("  CA Alt Algorithm: " + caAltPublicKey.getAlgorithm());
    }

    @Test
    @DisplayName("[TC-XBC-CERT-CAT] Verify: Catalyst Extensions Present")
    public void testCrossCompat_Verify_CatalystExtensionsPresent() throws Exception {
        File caFile = new File(FIXTURES + "/ca/ca.crt");
        if (!caFile.exists()) {
            System.out.println("Catalyst fixtures not found, skipping test");
            return;
        }

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509CertificateHolder holder = new X509CertificateHolder(caCert.getEncoded());

        // Get extension values
        Extension altSigAlg = holder.getExtension(OID_ALT_SIGNATURE_ALGORITHM);
        Extension altSigVal = holder.getExtension(OID_ALT_SIGNATURE_VALUE);
        Extension altPubKey = holder.getExtension(OID_ALT_SUBJECT_PUBLIC_KEY_INFO);

        assertNotNull(altSigAlg, "AltSignatureAlgorithm extension should exist");
        assertNotNull(altSigVal, "AltSignatureValue extension should exist");
        assertNotNull(altPubKey, "AltSubjectPublicKeyInfo extension should exist");

        // Verify extensions are non-critical (for backward compatibility)
        assertFalse(altSigAlg.isCritical(), "AltSignatureAlgorithm should be non-critical");
        assertFalse(altSigVal.isCritical(), "AltSignatureValue should be non-critical");
        assertFalse(altPubKey.isCritical(), "AltSubjectPublicKeyInfo should be non-critical");

        System.out.println("Catalyst extension structure: VALID");
        System.out.println("  All Catalyst extensions are non-critical (backward compatible)");
    }

    private X509Certificate loadCert(String path) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        try (FileInputStream fis = new FileInputStream(path)) {
            return (X509Certificate) cf.generateCertificate(fis);
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

    /**
     * Extract the alternative public key from the AltSubjectPublicKeyInfo extension.
     * The extension contains a SubjectPublicKeyInfo structure (same as standard SPKI).
     */
    private PublicKey extractAltPublicKey(Extension altPubKeyExt) throws Exception {
        // The extension value is a SubjectPublicKeyInfo
        SubjectPublicKeyInfo altSpki = SubjectPublicKeyInfo.getInstance(
            altPubKeyExt.getParsedValue());

        // Determine algorithm and use appropriate provider
        String algorithm = altSpki.getAlgorithm().getAlgorithm().getId();

        // All PQC algorithms (ML-DSA, SLH-DSA) are in the main BC provider
        String provider = "BC";

        KeyFactory keyFactory = KeyFactory.getInstance(
            getAlgorithmName(algorithm), provider);

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
            default: return oid; // Fall back to OID
        }
    }
}
