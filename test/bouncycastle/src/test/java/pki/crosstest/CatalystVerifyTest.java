package pki.crosstest;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

/**
 * Cross-test: Verify Catalyst Hybrid certificates with BouncyCastle.
 *
 * Catalyst certificates (ITU-T X.509 Section 9.8) contain:
 * - Classical signature in signatureValue
 * - PQC signature in AltSignatureValue extension (OID 2.5.29.74)
 * - PQC public key in AltSubjectPublicKeyInfo extension (OID 2.5.29.72)
 *
 * This test verifies the classical signature. Full dual-signature verification
 * requires custom parsing of the Catalyst extensions.
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

    @BeforeClass
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testCatalystCAClassicalSignature() throws Exception {
        File caFile = new File(FIXTURES + "/ca/ca.crt");
        if (!caFile.exists()) {
            System.out.println("Catalyst fixtures not found, skipping test");
            return;
        }

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        assertNotNull("Catalyst CA certificate should load", caCert);

        X509CertificateHolder holder = new X509CertificateHolder(caCert.getEncoded());

        // Verify classical signature
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue("Catalyst CA classical signature should verify",
            holder.isSignatureValid(verifier));

        // Check for Catalyst extensions
        boolean hasAltSigAlg = holder.getExtension(OID_ALT_SIGNATURE_ALGORITHM) != null;
        boolean hasAltSigVal = holder.getExtension(OID_ALT_SIGNATURE_VALUE) != null;
        boolean hasAltPubKey = holder.getExtension(OID_ALT_SUBJECT_PUBLIC_KEY_INFO) != null;

        System.out.println("Catalyst CA Classical verification: PASSED");
        System.out.println("  AltSignatureAlgorithm (2.5.29.73): " + hasAltSigAlg);
        System.out.println("  AltSignatureValue (2.5.29.74): " + hasAltSigVal);
        System.out.println("  AltSubjectPublicKeyInfo (2.5.29.72): " + hasAltPubKey);

        // Verify Catalyst extensions are present
        assertTrue("Catalyst cert should have AltSignatureAlgorithm", hasAltSigAlg);
        assertTrue("Catalyst cert should have AltSignatureValue", hasAltSigVal);
        assertTrue("Catalyst cert should have AltSubjectPublicKeyInfo", hasAltPubKey);
    }

    @Test
    public void testCatalystEndEntityClassicalSignature() throws Exception {
        File caFile = new File(FIXTURES + "/ca/ca.crt");
        if (!caFile.exists()) {
            System.out.println("Catalyst fixtures not found, skipping test");
            return;
        }

        String eeCertPath = findBundleCert(FIXTURES + "/ca/bundles");
        if (eeCertPath == null) {
            System.out.println("No Catalyst bundle certificate found, skipping EE test");
            return;
        }

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509Certificate eeCert = loadCert(eeCertPath);

        X509CertificateHolder holder = new X509CertificateHolder(eeCert.getEncoded());

        // Verify classical signature against CA
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue("Catalyst EE classical signature should verify",
            holder.isSignatureValid(verifier));

        // Check for Catalyst extensions
        boolean hasAltSigVal = holder.getExtension(OID_ALT_SIGNATURE_VALUE) != null;

        System.out.println("Catalyst EE Classical verification: PASSED");
        System.out.println("  Subject: " + eeCert.getSubjectX500Principal());
        System.out.println("  Has AltSignatureValue: " + hasAltSigVal);

        assertTrue("Catalyst EE cert should have AltSignatureValue", hasAltSigVal);
    }

    @Test
    public void testCatalystExtensionsPresent() throws Exception {
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

        assertNotNull("AltSignatureAlgorithm extension should exist", altSigAlg);
        assertNotNull("AltSignatureValue extension should exist", altSigVal);
        assertNotNull("AltSubjectPublicKeyInfo extension should exist", altPubKey);

        // Verify extensions are non-critical (for backward compatibility)
        assertFalse("AltSignatureAlgorithm should be non-critical", altSigAlg.isCritical());
        assertFalse("AltSignatureValue should be non-critical", altSigVal.isCritical());
        assertFalse("AltSubjectPublicKeyInfo should be non-critical", altPubKey.isCritical());

        System.out.println("Catalyst extension structure: VALID");
        System.out.println("  All Catalyst extensions are non-critical (backward compatible)");
    }

    private X509Certificate loadCert(String path) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        try (FileInputStream fis = new FileInputStream(path)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    private String findBundleCert(String bundlesDir) {
        File dir = new File(bundlesDir);
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
}
