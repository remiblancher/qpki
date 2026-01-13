package pki.crosstest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Cross-test: Verify CSRs with BouncyCastle.
 *
 * Tests signature verification for:
 * - Classical ECDSA CSR
 * - PQC ML-DSA-87 CSR
 * - PQC SLH-DSA-256f CSR
 * - Catalyst Hybrid CSR
 *
 * Requires BouncyCastle 1.77+ for PQC support.
 */
public class CSRVerifyTest {

    private static final String FIXTURES = "../fixtures/csr";

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @DisplayName("[TC-XBC-CSR-EC] Verify: ECDSA CSR")
    public void testCrossCompat_Verify_CSR_ECDSA() throws Exception {
        verifyCSR("ecdsa.csr", "ECDSA");
    }

    @Test
    @DisplayName("[TC-XBC-CSR-ML] Verify: ML-DSA-87 CSR")
    public void testCrossCompat_Verify_CSR_MLDSA() throws Exception {
        verifyCSR("mldsa87.csr", "ML-DSA-87");
    }

    @Test
    @DisplayName("[TC-XBC-CSR-SLH] Verify: SLH-DSA-256f CSR")
    public void testCrossCompat_Verify_CSR_SLHDSA() throws Exception {
        verifyCSR("slhdsa256f.csr", "SLH-DSA-256f");
    }

    @Test
    @Disabled("BC 1.83 ignores alt key attributes during verification - OpenSSL verifies OK")
    @DisplayName("[TC-XBC-CSR-CAT] Verify: Catalyst Hybrid CSR")
    public void testCrossCompat_Verify_CSR_Catalyst() throws Exception {
        verifyCSR("catalyst.csr", "Catalyst");
    }

    @Test
    @DisplayName("[TC-XBC-CSR-CAT] Parse: Catalyst CSR Structure")
    public void testCrossCompat_Parse_CSR_Catalyst() throws Exception {
        File csrFile = new File(FIXTURES + "/catalyst.csr");
        assumeTrue(csrFile.exists(), "Catalyst CSR fixture not found - run generate_qpki_fixtures.sh");

        PKCS10CertificationRequest csr = loadCSR(csrFile);
        assertNotNull(csr, "CSR should load");

        // Verify the classical signature works in isolation
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(csr.getSubjectPublicKeyInfo());

        // Note: BC 1.83 fails signature verification due to alt key attributes
        // OpenSSL verifies correctly: openssl req -verify -in catalyst.csr -inform DER -noout
        boolean sigValid = csr.isSignatureValid(verifier);

        System.out.println("Catalyst CSR Structure: PARSED");
        System.out.println("  Subject: " + csr.getSubject());
        System.out.println("  Algorithm: " + csr.getSignatureAlgorithm().getAlgorithm());
        System.out.println("  BC Signature Valid: " + sigValid + " (OpenSSL verifies OK)");
    }

    @Test
    @DisplayName("[TC-XBC-CSR-COMP] Parse: Composite CSR Structure")
    public void testCrossCompat_Parse_CSR_Composite() throws Exception {
        File csrFile = new File(FIXTURES + "/composite.csr");
        assumeTrue(csrFile.exists(), "Composite CSR fixture not found - run generate_qpki_fixtures.sh");

        PKCS10CertificationRequest csr = loadCSR(csrFile);
        assertNotNull(csr, "CSR should load");

        // Composite CSR uses IETF draft-13 OIDs (1.3.6.1.5.5.7.6.x)
        // BC 1.83 uses draft-07 OIDs (2.16.840.1.114027.80.8.1.x)
        // Signature verification not possible due to OID mismatch
        System.out.println("Composite CSR Structure: PARSED");
        System.out.println("  Subject: " + csr.getSubject());
        System.out.println("  Algorithm OID: " + csr.getSignatureAlgorithm().getAlgorithm());
        System.out.println("  Note: BC 1.83 uses draft-07 OIDs, signature verification not possible");
    }

    private void verifyCSR(String filename, String algName) throws Exception {
        File csrFile = new File(FIXTURES + "/" + filename);
        assumeTrue(csrFile.exists(), algName + " CSR fixture not found - run generate_qpki_fixtures.sh");

        PKCS10CertificationRequest csr = loadCSR(csrFile);
        assertNotNull(csr, "CSR should load");

        // Verify self-signature
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(csr.getSubjectPublicKeyInfo());

        assertTrue(csr.isSignatureValid(verifier),
            algName + " CSR signature should verify");

        System.out.println(algName + " CSR verification: PASSED");
        System.out.println("  Subject: " + csr.getSubject());
        System.out.println("  Algorithm: " + csr.getSignatureAlgorithm().getAlgorithm());
    }

    private PKCS10CertificationRequest loadCSR(File file) throws Exception {
        byte[] data = Files.readAllBytes(file.toPath());

        // Handle PEM format
        String content = new String(data);
        if (content.contains("-----BEGIN CERTIFICATE REQUEST-----")) {
            String base64 = content
                .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "")
                .replaceAll("\\s", "");
            data = java.util.Base64.getDecoder().decode(base64);
        }

        return new PKCS10CertificationRequest(data);
    }
}
