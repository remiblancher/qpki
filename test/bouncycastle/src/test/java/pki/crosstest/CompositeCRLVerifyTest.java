package pki.crosstest;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cross-test: Verify IETF Composite CRLs with BouncyCastle.
 *
 * Composite CRLs (IETF draft-ietf-lamps-pq-composite-sigs-13) contain:
 * - Single composite signature (both ML-DSA + ECDSA encoded together)
 * - Composite algorithm OID identifies the algorithm pair
 *
 * IMPORTANT: BouncyCastle 1.83 supports draft-07 with Entrust OIDs (2.16.840.1.114027.80.8.1.x),
 * while our implementation uses draft-13 with IETF standard OIDs (1.3.6.1.5.5.7.6.x).
 * Signature verification is SKIPPED until BC migrates to the IETF standard OIDs.
 *
 * OID Arc (IETF draft-13): 1.3.6.1.5.5.7.6.x (id-smime algorithms)
 * - MLDSA44-ECDSA-P256-SHA256: 1.3.6.1.5.5.7.6.40
 * - MLDSA65-ECDSA-P256-SHA512: 1.3.6.1.5.5.7.6.45
 * - MLDSA87-ECDSA-P384-SHA512: 1.3.6.1.5.5.7.6.49
 */
public class CompositeCRLVerifyTest {

    private static final String FIXTURES = "../fixtures/composite";

    // IETF Composite OID prefix (id-smime algorithms arc) - draft-13
    private static final String COMPOSITE_OID_PREFIX = "1.3.6.1.5.5.7.6";

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test that composite CRL can be loaded and parsed by BouncyCastle.
     *
     * Note: Signature verification is SKIPPED because BC 1.83 implements draft-07
     * (Entrust OIDs) while we implement draft-13 (IETF standard OIDs).
     */
    @Test
    @DisplayName("[CrossCompat] Verify: Composite CRL Parsing")
    public void testCrossCompat_Verify_CompositeCRL_Parsing() throws Exception {
        File crlFile = new File(FIXTURES + "/ca/crl/ca.crl");

        if (!crlFile.exists()) {
            System.out.println("Composite fixtures not found, skipping test");
            System.out.println("Run ./test/generate_qpki_fixtures.sh first");
            return;
        }

        X509CRLHolder crlHolder = loadCRL(crlFile.getAbsolutePath());
        assertNotNull(crlHolder, "Composite CRL should load");

        // Check algorithm OID is composite (IETF arc)
        String algOid = crlHolder.toASN1Structure().getSignatureAlgorithm().getAlgorithm().getId();
        System.out.println("Composite CRL Signature Algorithm OID: " + algOid);

        assertTrue(algOid.startsWith(COMPOSITE_OID_PREFIX),
            "Should be IETF composite OID (1.3.6.1.5.5.7.6.x), got: " + algOid);

        // NOTE: Signature verification SKIPPED
        System.out.println("Composite CRL parsing: PASSED");
        System.out.println("  Issuer: " + crlHolder.getIssuer());
        System.out.println("  Signature verification: SKIPPED (BC 1.83 supports draft-07, we use draft-13)");
        System.out.println("  See: https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/");
    }

    @Test
    @DisplayName("[CrossCompat] Verify: Composite CRL Algorithm OID")
    public void testCrossCompat_Verify_CompositeCRL_AlgorithmOID() throws Exception {
        File crlFile = new File(FIXTURES + "/ca/crl/ca.crl");

        if (!crlFile.exists()) {
            System.out.println("Composite fixtures not found, skipping test");
            return;
        }

        X509CRLHolder crlHolder = loadCRL(crlFile.getAbsolutePath());
        String algOid = crlHolder.toASN1Structure().getSignatureAlgorithm().getAlgorithm().getId();

        System.out.println("Composite CRL OID:");
        System.out.println("  Signature Algorithm: " + algOid);

        // Verify it's an IETF composite OID
        assertTrue(algOid.startsWith(COMPOSITE_OID_PREFIX),
            "Signature algorithm should be IETF composite OID");

        // Identify specific algorithm combination (IETF OIDs from draft-13)
        if (algOid.endsWith(".49")) {
            System.out.println("  Algorithm: MLDSA87-ECDSA-P384-SHA512");
        } else if (algOid.endsWith(".45")) {
            System.out.println("  Algorithm: MLDSA65-ECDSA-P256-SHA512");
        } else if (algOid.endsWith(".40")) {
            System.out.println("  Algorithm: MLDSA44-ECDSA-P256-SHA256");
        } else {
            System.out.println("  Algorithm: Unknown composite variant");
        }

        System.out.println();
        System.out.println("NOTE: Our implementation uses IETF draft-13 standard OIDs.");
        System.out.println("  IETF OID arc: 1.3.6.1.5.5.7.6.x (id-smime algorithms)");
        System.out.println("  BC 1.83 uses: 2.16.840.1.114027.80.8.1.x (Entrust draft-07)");
    }

    @Test
    @DisplayName("[CrossCompat] Verify: Composite CRL Structure")
    public void testCrossCompat_Verify_CompositeCRL_Structure() throws Exception {
        File crlFile = new File(FIXTURES + "/ca/crl/ca.crl");

        if (!crlFile.exists()) {
            System.out.println("Composite fixtures not found, skipping test");
            return;
        }

        X509CRLHolder crlHolder = loadCRL(crlFile.getAbsolutePath());

        // Verify CRL structure is valid
        assertNotNull(crlHolder.getIssuer(), "CRL should have issuer");
        assertNotNull(crlHolder.getThisUpdate(), "CRL should have thisUpdate");
        assertNotNull(crlHolder.getNextUpdate(), "CRL should have nextUpdate");

        // Verify signature value is present and non-empty
        byte[] signatureValue = crlHolder.toASN1Structure().getSignature().getBytes();
        assertTrue(signatureValue.length > 0, "CRL should have signature value");

        // Composite signatures are larger than classical (contains both ML-DSA + ECDSA)
        // ML-DSA-87 signature is ~4627 bytes, ECDSA-P384 is ~96 bytes
        assertTrue(signatureValue.length > 1000,
            "Composite signature should be larger than classical (contains both signatures)");

        System.out.println("Composite CRL structure: VALID");
        System.out.println("  Issuer: " + crlHolder.getIssuer());
        System.out.println("  This Update: " + crlHolder.getThisUpdate());
        System.out.println("  Next Update: " + crlHolder.getNextUpdate());
        System.out.println("  Signature Size: " + signatureValue.length + " bytes");
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
}
