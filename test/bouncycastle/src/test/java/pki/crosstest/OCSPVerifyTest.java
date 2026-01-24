package pki.crosstest;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Cross-test: Verify OCSP Responses with BouncyCastle.
 *
 * This test validates that our OCSP responses are correctly formatted
 * and can be verified by an independent implementation.
 *
 * Tests all algorithm types:
 * - Classical ECDSA
 * - PQC ML-DSA-87 (FIPS 204)
 * - PQC SLH-DSA (FIPS 205)
 * - Catalyst Hybrid (ECDSA + ML-DSA)
 * - Composite Hybrid (IETF draft-13)
 */
public class OCSPVerifyTest {

    private static final String FIXTURES = "../fixtures";

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // =========================================================================
    // Classical ECDSA
    // =========================================================================

    @Test
    @DisplayName("[TC-XBC-OCSP-EC] Verify: OCSP Classical ECDSA")
    public void testCrossCompat_Verify_OCSP_Classical() throws Exception {
        Path ocspFile = Paths.get(FIXTURES, "classical/ecdsa/ocsp-good.der");
        assertTrue(Files.exists(ocspFile), "Classical OCSP fixture must exist");

        verifyOCSPResponse(Files.readAllBytes(ocspFile), "Classical ECDSA");
    }

    // =========================================================================
    // PQC ML-DSA-87
    // =========================================================================

    @Test
    @DisplayName("[TC-XBC-OCSP-ML] Verify: OCSP ML-DSA-87")
    public void testCrossCompat_Verify_OCSP_MLDSA() throws Exception {
        Path ocspFile = Paths.get(FIXTURES, "pqc/mldsa/ocsp-good.der");
        assertTrue(Files.exists(ocspFile), "ML-DSA OCSP fixture must exist");

        verifyOCSPResponse(Files.readAllBytes(ocspFile), "ML-DSA-87");
    }

    // =========================================================================
    // PQC SLH-DSA
    // =========================================================================

    @Test
    @DisplayName("[TC-XBC-OCSP-SLH] Verify: OCSP SLH-DSA")
    public void testCrossCompat_Verify_OCSP_SLHDSA() throws Exception {
        Path ocspFile = Paths.get(FIXTURES, "pqc/slhdsa/ocsp-good.der");
        assertTrue(Files.exists(ocspFile), "SLH-DSA OCSP fixture must exist");

        verifyOCSPResponse(Files.readAllBytes(ocspFile), "SLH-DSA");
    }

    // =========================================================================
    // Catalyst Hybrid (ECDSA + ML-DSA)
    // =========================================================================

    @Test
    @DisplayName("[TC-XBC-OCSP-CAT] Verify: OCSP Catalyst Hybrid")
    public void testCrossCompat_Verify_OCSP_Catalyst() throws Exception {
        Path ocspFile = Paths.get(FIXTURES, "catalyst/ocsp-good.der");
        assertTrue(Files.exists(ocspFile), "Catalyst OCSP fixture must exist");

        verifyOCSPResponse(Files.readAllBytes(ocspFile), "Catalyst Hybrid");
    }

    // =========================================================================
    // Composite Hybrid (IETF draft-13)
    // =========================================================================

    @Test
    @Disabled("BC 1.83 uses Composite draft-07, we use IETF draft-13")
    @DisplayName("[TC-XBC-OCSP-COMP] Verify: OCSP Composite Hybrid")
    public void testCrossCompat_Verify_OCSP_Composite() throws Exception {
        Path ocspFile = Paths.get(FIXTURES, "composite/ocsp-good.der");
        assertTrue(Files.exists(ocspFile), "Composite OCSP fixture must exist");

        verifyOCSPResponse(Files.readAllBytes(ocspFile), "Composite Hybrid");
    }

    @Test
    @DisplayName("[TC-XBC-OCSP-COMP] Parse: OCSP Composite Structure")
    public void testCrossCompat_Parse_OCSP_Composite() throws Exception {
        Path ocspFile = Paths.get(FIXTURES, "composite/ocsp-good.der");
        assumeTrue(Files.exists(ocspFile), "Composite OCSP fixture not generated");

        OCSPResp ocspResp = new OCSPResp(Files.readAllBytes(ocspFile));
        assertEquals(OCSPResp.SUCCESSFUL, ocspResp.getStatus(), "Response status should be SUCCESSFUL");

        BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
        assertNotNull(basicResp, "BasicOCSPResp should exist");

        String sigAlgOid = basicResp.getSignatureAlgOID().getId();
        SingleResp[] responses = basicResp.getResponses();
        assertTrue(responses.length > 0, "Should have responses");

        System.out.println("Composite OCSP Structure: PARSED");
        System.out.println("  Signature Algorithm OID: " + sigAlgOid);
        System.out.println("  Certificate Status: " + (responses[0].getCertStatus() == null ? "GOOD" : "OTHER"));
        System.out.println("  Note: Signature verification skipped (BC draft-07 vs QPKI draft-13)");
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    private void verifyOCSPResponse(byte[] responseBytes, String algName) throws Exception {
        // Parse OCSP response
        OCSPResp ocspResp = new OCSPResp(responseBytes);

        // Check response status
        assertEquals(OCSPResp.SUCCESSFUL, ocspResp.getStatus(),
            algName + " OCSP response status should be SUCCESSFUL");
        System.out.println(algName + " OCSP Response Status: SUCCESSFUL");

        // Get BasicOCSPResp
        Object respObject = ocspResp.getResponseObject();
        assertNotNull(respObject, "Response object should not be null");
        assertTrue(respObject instanceof BasicOCSPResp,
            "Response should be BasicOCSPResp");

        BasicOCSPResp basicResp = (BasicOCSPResp) respObject;

        // Print signature algorithm
        String sigAlgOid = basicResp.getSignatureAlgOID().getId();
        System.out.println(algName + " Signature Algorithm OID: " + sigAlgOid);

        // Check responses
        SingleResp[] responses = basicResp.getResponses();
        assertTrue(responses.length > 0, "Should have at least one response");

        // Check first response status
        SingleResp singleResp = responses[0];
        CertificateStatus status = singleResp.getCertStatus();
        assertNull(status, algName + " Certificate status should be GOOD (null)");
        System.out.println(algName + " Certificate Status: GOOD");

        // Print timestamps
        System.out.println(algName + " This Update: " + singleResp.getThisUpdate());
        if (singleResp.getNextUpdate() != null) {
            System.out.println(algName + " Next Update: " + singleResp.getNextUpdate());
        }

        // Get responder certificate
        X509CertificateHolder[] certs = basicResp.getCerts();
        assertTrue(certs.length > 0, "Responder certificate should be included");

        X509CertificateHolder responderCert = certs[0];
        System.out.println(algName + " Responder: " + responderCert.getSubject());

        // Verify signature
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(responderCert);

        assertTrue(basicResp.isSignatureValid(verifier),
            algName + " OCSP signature verification must succeed");
        System.out.println(algName + " Signature: VERIFIED");
    }
}
