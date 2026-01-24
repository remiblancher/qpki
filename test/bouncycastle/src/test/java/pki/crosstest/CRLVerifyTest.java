package pki.crosstest;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Cross-test: Verify CRLs (Classical and PQC) with BouncyCastle.
 *
 * Tests signature verification for:
 * - Classical ECDSA CRLs
 * - PQC ML-DSA CRLs
 * - PQC SLH-DSA CRLs
 */
public class CRLVerifyTest {

    private static final String FIXTURES_CLASSICAL = "../fixtures/classical/ecdsa";
    private static final String FIXTURES_PQC_MLDSA = "../fixtures/pqc/mldsa";
    private static final String FIXTURES_PQC_SLHDSA = "../fixtures/pqc/slhdsa";

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @DisplayName("[TC-XBC-CRL-EC] Verify: Classical ECDSA CRL")
    public void testCrossCompat_Verify_ClassicalCRL() throws Exception {
        File crlFile = new File(FIXTURES_CLASSICAL + "/ca/crl/ca.crl");
        File caFile = new File(FIXTURES_CLASSICAL + "/ca/ca.crt");

        assumeTrue(crlFile.exists() && caFile.exists(), "Classical fixtures not found - run generate_qpki_fixtures.sh");

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509CRLHolder crlHolder = loadCRL(crlFile.getAbsolutePath());

        assertNotNull(crlHolder, "CRL should load");

        // Verify CRL signature
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue(crlHolder.isSignatureValid(verifier),
            "Classical CRL signature should verify");

        System.out.println("Classical CRL verification: PASSED");
        System.out.println("  Issuer: " + crlHolder.getIssuer());
        System.out.println("  Algorithm: " + crlHolder.toASN1Structure().getSignatureAlgorithm().getAlgorithm());
    }

    @Test
    @DisplayName("[TC-XBC-CRL-ML] Verify: PQC ML-DSA CRL")
    public void testCrossCompat_Verify_PQCCRL_MLDSA() throws Exception {
        File crlFile = new File(FIXTURES_PQC_MLDSA + "/ca/crl/ca.crl");
        File caFile = new File(FIXTURES_PQC_MLDSA + "/ca/ca.crt");

        assumeTrue(crlFile.exists() && caFile.exists(), "PQC ML-DSA fixtures not found - run generate_qpki_fixtures.sh");

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509CRLHolder crlHolder = loadCRL(crlFile.getAbsolutePath());

        assertNotNull(crlHolder, "CRL should load");

        // Verify CRL signature using PQC algorithm
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue(crlHolder.isSignatureValid(verifier),
            "PQC ML-DSA CRL signature should verify");

        System.out.println("PQC ML-DSA CRL verification: PASSED");
        System.out.println("  Issuer: " + crlHolder.getIssuer());
        System.out.println("  Algorithm: " + crlHolder.toASN1Structure().getSignatureAlgorithm().getAlgorithm());
    }

    @Test
    @DisplayName("[TC-XBC-CRL-SLH] Verify: PQC SLH-DSA CRL")
    public void testCrossCompat_Verify_PQCCRL_SLHDSA() throws Exception {
        File crlFile = new File(FIXTURES_PQC_SLHDSA + "/ca/crl/ca.crl");
        File caFile = new File(FIXTURES_PQC_SLHDSA + "/ca/ca.crt");

        assumeTrue(crlFile.exists() && caFile.exists(), "PQC SLH-DSA fixtures not found - run generate_qpki_fixtures.sh");

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509CRLHolder crlHolder = loadCRL(crlFile.getAbsolutePath());

        assertNotNull(crlHolder, "CRL should load");

        // Verify CRL signature using PQC algorithm
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue(crlHolder.isSignatureValid(verifier),
            "PQC SLH-DSA CRL signature should verify");

        System.out.println("PQC SLH-DSA CRL verification: PASSED");
        System.out.println("  Issuer: " + crlHolder.getIssuer());
        System.out.println("  Algorithm: " + crlHolder.toASN1Structure().getSignatureAlgorithm().getAlgorithm());
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
            // Extract base64 content between headers
            String base64 = content
                .replace("-----BEGIN X509 CRL-----", "")
                .replace("-----END X509 CRL-----", "")
                .replaceAll("\\s", "");
            data = java.util.Base64.getDecoder().decode(base64);
        }

        return new X509CRLHolder(data);
    }
}
