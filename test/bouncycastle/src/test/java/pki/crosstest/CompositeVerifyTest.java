package pki.crosstest;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Cross-test: Verify IETF Composite certificates with BouncyCastle.
 *
 * Composite certificates (IETF draft-ietf-lamps-pq-composite-sigs-13) contain:
 * - Single composite public key (both keys encoded together)
 * - Single composite signature (both signatures encoded together)
 * - Composite algorithm OID identifies the algorithm pair
 *
 * IMPORTANT: BouncyCastle 1.83 supports draft-07 with Entrust OIDs (2.16.840.1.114027.80.8.1.x),
 * while our implementation uses draft-13 with IETF standard OIDs (1.3.6.1.5.5.7.6.x).
 * Signature verification is SKIPPED until BC migrates to the IETF standard OIDs.
 *
 * OID Arc (IETF draft-13): 1.3.6.1.5.5.7.6.x (id-smime algorithms)
 * Only IANA-allocated OIDs are supported:
 * - MLDSA65-ECDSA-P256-SHA512: 1.3.6.1.5.5.7.6.45
 * - MLDSA65-ECDSA-P384-SHA512: 1.3.6.1.5.5.7.6.46
 * - MLDSA87-ECDSA-P521-SHA512: 1.3.6.1.5.5.7.6.54
 */
public class CompositeVerifyTest {

    private static final String FIXTURES = "../fixtures/composite";

    // IETF Composite OID prefix (id-smime algorithms arc) - draft-13
    private static final String COMPOSITE_OID_PREFIX = "1.3.6.1.5.5.7.6";

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test that composite CA certificate can be loaded and parsed by BouncyCastle.
     *
     * Note: Signature verification is SKIPPED because BC 1.83 implements draft-07
     * (Entrust OIDs) while we implement draft-13 (IETF standard OIDs).
     */
    @Test
    @DisplayName("[TC-XBC-CERT-COMP] Parse: Composite CA Certificate")
    public void testCrossCompat_Verify_CompositeCASignature() throws Exception {
        File caFile = new File(FIXTURES + "/ca/ca.crt");
        assumeTrue(caFile.exists(), "Composite fixtures not found - run generate_qpki_fixtures.sh");

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        assertNotNull(caCert, "Composite CA certificate should load");

        X509CertificateHolder holder = new X509CertificateHolder(caCert.getEncoded());

        // Check algorithm OID is composite (IETF arc)
        String algOid = holder.getSignatureAlgorithm().getAlgorithm().getId();
        System.out.println("Composite CA Signature Algorithm OID: " + algOid);

        assertTrue(algOid.startsWith(COMPOSITE_OID_PREFIX),
            "Should be IETF composite OID (1.3.6.1.5.5.7.6.x)");

        // NOTE: Signature verification SKIPPED
        // BouncyCastle 1.83 supports draft-07 with Entrust OIDs (2.16.840.1.114027.80.8.1.x)
        // Our implementation uses draft-13 with IETF standard OIDs (1.3.6.1.5.5.7.6.x)
        // BC does not recognize our OIDs, so verification fails with "NoSuchAlgorithmException"
        System.out.println("Composite CA parsing: PASSED");
        System.out.println("  Signature verification: SKIPPED (BC 1.83 supports draft-07, we use draft-13)");
        System.out.println("  See: https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/");
    }

    /**
     * Test that composite end-entity certificate can be loaded and parsed.
     *
     * Note: Signature verification is SKIPPED due to draft version mismatch.
     */
    @Test
    @DisplayName("[TC-XBC-CERT-COMP] Parse: Composite EE Certificate")
    public void testCrossCompat_Verify_CompositeEndEntitySignature() throws Exception {
        File caFile = new File(FIXTURES + "/ca/ca.crt");
        assumeTrue(caFile.exists(), "Composite fixtures not found - run generate_qpki_fixtures.sh");

        String eeCertPath = findCredentialCert(FIXTURES + "/credentials");
        assumeTrue(eeCertPath != null, "No Composite credential certificate found - run generate_qpki_fixtures.sh");

        X509Certificate eeCert = loadCert(eeCertPath);

        X509CertificateHolder holder = new X509CertificateHolder(eeCert.getEncoded());

        // Check algorithm OID
        String algOid = holder.getSignatureAlgorithm().getAlgorithm().getId();
        System.out.println("Composite EE Signature Algorithm OID: " + algOid);

        assertTrue(algOid.startsWith(COMPOSITE_OID_PREFIX),
            "Should be IETF composite OID");

        // NOTE: Signature verification SKIPPED (same reason as CA test)
        System.out.println("Composite EE parsing: PASSED");
        System.out.println("  Subject: " + eeCert.getSubjectX500Principal());
        System.out.println("  Signature verification: SKIPPED (BC 1.83 supports draft-07, we use draft-13)");
    }

    @Test
    @DisplayName("[TC-XBC-CERT-COMP] Parse: Composite Algorithm OID")
    public void testCrossCompat_Verify_CompositeAlgorithmOID() throws Exception {
        File caFile = new File(FIXTURES + "/ca/ca.crt");
        assumeTrue(caFile.exists(), "Composite fixtures not found - run generate_qpki_fixtures.sh");

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509CertificateHolder holder = new X509CertificateHolder(caCert.getEncoded());

        String algOid = holder.getSignatureAlgorithm().getAlgorithm().getId();
        String pubKeyAlgOid = holder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId();

        System.out.println("Composite Certificate OIDs:");
        System.out.println("  Signature Algorithm: " + algOid);
        System.out.println("  Public Key Algorithm: " + pubKeyAlgOid);

        // Both should be IETF composite OIDs (draft-13)
        assertTrue(algOid.startsWith(COMPOSITE_OID_PREFIX),
            "Signature algorithm should be IETF composite OID");
        assertTrue(pubKeyAlgOid.startsWith(COMPOSITE_OID_PREFIX),
            "Public key algorithm should be IETF composite OID");

        // Identify specific algorithm combination (IANA-allocated OIDs from draft-13)
        if (algOid.endsWith(".45")) {
            System.out.println("  Algorithm: MLDSA65-ECDSA-P256-SHA512");
        } else if (algOid.endsWith(".46")) {
            System.out.println("  Algorithm: MLDSA65-ECDSA-P384-SHA512");
        } else if (algOid.endsWith(".54")) {
            System.out.println("  Algorithm: MLDSA87-ECDSA-P521-SHA512");
        } else {
            System.out.println("  Algorithm: Unknown composite variant");
        }

        System.out.println();
        System.out.println("NOTE: Our implementation uses IETF draft-13 standard OIDs.");
        System.out.println("  IETF OID arc: 1.3.6.1.5.5.7.6.x (id-smime algorithms)");
        System.out.println("  BC 1.83 uses: 2.16.840.1.114027.80.8.1.x (Entrust draft-07)");
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
}
