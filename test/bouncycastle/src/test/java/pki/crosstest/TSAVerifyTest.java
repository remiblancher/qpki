package pki.crosstest;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cross-test: Verify TSA Tokens (RFC 3161) with BouncyCastle.
 *
 * This test validates that our timestamp tokens are correctly formatted
 * and can be verified by an independent implementation.
 *
 * Tests all algorithm types:
 * - Classical ECDSA
 * - PQC ML-DSA-87 (FIPS 204)
 * - PQC SLH-DSA (FIPS 205)
 * - Catalyst Hybrid (ECDSA + ML-DSA)
 * - Composite Hybrid (IETF draft-13) - DISABLED: BC 1.83 uses draft-07
 */
public class TSAVerifyTest {

    private static final String FIXTURES = "../fixtures";
    // Note: echo adds a newline, so we must include it for hash to match
    private static final String TEST_DATA = "Test data for cross-compatibility testing\n";

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // =========================================================================
    // Classical ECDSA
    // =========================================================================

    @Test
    @DisplayName("[CrossCompat] Verify: TSA Classical ECDSA")
    public void testCrossCompat_Verify_TSA_Classical() throws Exception {
        Path tsaFile = Paths.get(FIXTURES, "classical/timestamp.tsr");
        assertTrue(Files.exists(tsaFile), "Classical TSA fixture must exist");

        verifyTSAToken(Files.readAllBytes(tsaFile), "Classical ECDSA");
    }

    // =========================================================================
    // PQC ML-DSA-87
    // =========================================================================

    @Test
    @DisplayName("[CrossCompat] Verify: TSA ML-DSA-87")
    public void testCrossCompat_Verify_TSA_MLDSA() throws Exception {
        Path tsaFile = Paths.get(FIXTURES, "pqc/mldsa/timestamp.tsr");
        assertTrue(Files.exists(tsaFile), "ML-DSA TSA fixture must exist");

        verifyTSAToken(Files.readAllBytes(tsaFile), "ML-DSA-87");
    }

    // =========================================================================
    // PQC SLH-DSA
    // =========================================================================

    @Test
    @DisplayName("[CrossCompat] Verify: TSA SLH-DSA")
    public void testCrossCompat_Verify_TSA_SLHDSA() throws Exception {
        Path tsaFile = Paths.get(FIXTURES, "pqc/slhdsa/timestamp.tsr");
        assertTrue(Files.exists(tsaFile), "SLH-DSA TSA fixture must exist");

        verifyTSAToken(Files.readAllBytes(tsaFile), "SLH-DSA");
    }

    // =========================================================================
    // Catalyst Hybrid (ECDSA + ML-DSA)
    // =========================================================================

    @Test
    @DisplayName("[CrossCompat] Verify: TSA Catalyst Hybrid")
    public void testCrossCompat_Verify_TSA_Catalyst() throws Exception {
        Path tsaFile = Paths.get(FIXTURES, "catalyst/timestamp.tsr");
        assertTrue(Files.exists(tsaFile), "Catalyst TSA fixture must exist");

        verifyTSAToken(Files.readAllBytes(tsaFile), "Catalyst Hybrid");
    }

    // =========================================================================
    // Composite Hybrid (IETF draft-13)
    // =========================================================================

    @Test
    @Disabled("BC 1.83 uses Composite draft-07, we use IETF draft-13")
    @DisplayName("[CrossCompat] Verify: TSA Composite Hybrid")
    public void testCrossCompat_Verify_TSA_Composite() throws Exception {
        Path tsaFile = Paths.get(FIXTURES, "composite/timestamp.tsr");
        assertTrue(Files.exists(tsaFile), "Composite TSA fixture must exist");

        verifyTSAToken(Files.readAllBytes(tsaFile), "Composite Hybrid");
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    @SuppressWarnings("unchecked")
    private void verifyTSAToken(byte[] tokenBytes, String algName) throws Exception {
        // Parse TSA response
        TimeStampResponse tsResp = new TimeStampResponse(tokenBytes);

        // Check response status (0 = granted)
        assertEquals(0, tsResp.getStatus(),
            algName + " TSA response status should be GRANTED (0)");
        System.out.println(algName + " TSA Response Status: GRANTED");

        // Get timestamp token
        TimeStampToken token = tsResp.getTimeStampToken();
        assertNotNull(token, "Timestamp token should not be null");

        // Get token info
        TimeStampTokenInfo info = token.getTimeStampInfo();
        assertNotNull(info, "Token info should not be null");

        // Print timestamp info
        System.out.println(algName + " GenTime: " + info.getGenTime());
        System.out.println(algName + " Serial: " + info.getSerialNumber());

        // Print hash algorithm
        ASN1ObjectIdentifier hashAlgOid = info.getMessageImprintAlgOID();
        System.out.println(algName + " Hash Algorithm OID: " + hashAlgOid.getId());

        // Verify message imprint (hash of original data)
        String hashAlgName = getHashAlgorithmName(hashAlgOid.getId());
        MessageDigest md = MessageDigest.getInstance(hashAlgName, "BC");
        byte[] expectedHash = md.digest(TEST_DATA.getBytes());
        byte[] actualHash = info.getMessageImprintDigest();

        assertArrayEquals(expectedHash, actualHash,
            algName + " Message imprint must match hash of original data");
        System.out.println(algName + " MessageImprint: VERIFIED");

        // Get TSA certificate
        Store<X509CertificateHolder> certStore = token.getCertificates();
        Collection<X509CertificateHolder> certs = certStore.getMatches(token.getSID());
        assertFalse(certs.isEmpty(), "TSA certificate should be included");

        X509CertificateHolder tsaCert = certs.iterator().next();
        System.out.println(algName + " TSA: " + tsaCert.getSubject());

        // Verify signature
        SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
            .setProvider("BC")
            .build(tsaCert);

        token.validate(verifier);
        System.out.println(algName + " Signature: VERIFIED");
    }

    /**
     * Map hash algorithm OID to algorithm name
     */
    private String getHashAlgorithmName(String oid) {
        switch (oid) {
            case "2.16.840.1.101.3.4.2.1":  // SHA-256
                return "SHA-256";
            case "2.16.840.1.101.3.4.2.2":  // SHA-384
                return "SHA-384";
            case "2.16.840.1.101.3.4.2.3":  // SHA-512
                return "SHA-512";
            case "2.16.840.1.101.3.4.2.8":  // SHA3-256
                return "SHA3-256";
            case "2.16.840.1.101.3.4.2.9":  // SHA3-384
                return "SHA3-384";
            case "2.16.840.1.101.3.4.2.10": // SHA3-512
                return "SHA3-512";
            default:
                return "SHA-256"; // Default fallback
        }
    }
}
