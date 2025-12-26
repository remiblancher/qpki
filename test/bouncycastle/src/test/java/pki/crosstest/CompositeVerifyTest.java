package pki.crosstest;

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
 * Cross-test: Verify IETF Composite certificates with BouncyCastle.
 *
 * Composite certificates (IETF draft-ietf-lamps-pq-composite-sigs-13) contain:
 * - Single composite public key (both keys encoded together)
 * - Single composite signature (both signatures encoded together)
 * - Composite algorithm OID identifies the algorithm pair
 *
 * BouncyCastle 1.83+ supports IETF Composite signatures natively.
 *
 * OID Arc: 2.16.840.1.114027.80.9.1.x (Entrust)
 * - MLDSA87-ECDSA-P384-SHA512: 2.16.840.1.114027.80.9.1.32
 * - MLDSA65-ECDSA-P256-SHA512: 2.16.840.1.114027.80.9.1.28
 */
public class CompositeVerifyTest {

    private static final String FIXTURES = "../fixtures/composite";

    // IETF Composite OID prefix (Entrust arc)
    private static final String COMPOSITE_OID_PREFIX = "2.16.840.1.114027.80.9.1";

    @BeforeClass
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testCompositeCASignature() throws Exception {
        File caFile = new File(FIXTURES + "/ca/ca.crt");
        if (!caFile.exists()) {
            System.out.println("Composite fixtures not found, skipping test");
            System.out.println("Run ./test/generate_fixtures.sh first");
            return;
        }

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        assertNotNull("Composite CA certificate should load", caCert);

        X509CertificateHolder holder = new X509CertificateHolder(caCert.getEncoded());

        // Check algorithm OID is composite
        String algOid = holder.getSignatureAlgorithm().getAlgorithm().getId();
        System.out.println("Composite CA Signature Algorithm OID: " + algOid);

        assertTrue("Should be composite OID (Entrust arc)",
            algOid.startsWith(COMPOSITE_OID_PREFIX));

        // Verify composite signature (requires BouncyCastle 1.79+)
        try {
            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                .build(caCert.getPublicKey());

            boolean valid = holder.isSignatureValid(verifier);
            assertTrue("Composite CA signature should verify", valid);

            System.out.println("Composite CA verification: PASSED");
            System.out.println("  Both ML-DSA and ECDSA signatures verified by BouncyCastle");
        } catch (Exception e) {
            System.out.println("Composite CA verification failed: " + e.getMessage());
            System.out.println("This requires BouncyCastle 1.83+ for composite support.");
            // Print stack trace for debugging
            e.printStackTrace();
            fail("Composite signature verification failed: " + e.getMessage());
        }
    }

    @Test
    public void testCompositeEndEntitySignature() throws Exception {
        File caFile = new File(FIXTURES + "/ca/ca.crt");
        if (!caFile.exists()) {
            System.out.println("Composite fixtures not found, skipping test");
            return;
        }

        String eeCertPath = findBundleCert(FIXTURES + "/ca/bundles");
        if (eeCertPath == null) {
            System.out.println("No Composite bundle certificate found, skipping EE test");
            return;
        }

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509Certificate eeCert = loadCert(eeCertPath);

        X509CertificateHolder holder = new X509CertificateHolder(eeCert.getEncoded());

        // Check algorithm OID
        String algOid = holder.getSignatureAlgorithm().getAlgorithm().getId();
        System.out.println("Composite EE Signature Algorithm OID: " + algOid);

        // Verify against CA's composite public key
        try {
            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                .build(caCert.getPublicKey());

            boolean valid = holder.isSignatureValid(verifier);
            assertTrue("Composite EE signature should verify", valid);

            System.out.println("Composite EE verification: PASSED");
            System.out.println("  Subject: " + eeCert.getSubjectX500Principal());
        } catch (Exception e) {
            System.out.println("Composite EE verification failed: " + e.getMessage());
            e.printStackTrace();
            fail("Composite EE signature verification failed: " + e.getMessage());
        }
    }

    @Test
    public void testCompositeAlgorithmOID() throws Exception {
        File caFile = new File(FIXTURES + "/ca/ca.crt");
        if (!caFile.exists()) {
            System.out.println("Composite fixtures not found, skipping test");
            return;
        }

        X509Certificate caCert = loadCert(caFile.getAbsolutePath());
        X509CertificateHolder holder = new X509CertificateHolder(caCert.getEncoded());

        String algOid = holder.getSignatureAlgorithm().getAlgorithm().getId();
        String pubKeyAlgOid = holder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId();

        System.out.println("Composite Certificate OIDs:");
        System.out.println("  Signature Algorithm: " + algOid);
        System.out.println("  Public Key Algorithm: " + pubKeyAlgOid);

        // Both should be composite OIDs
        assertTrue("Signature algorithm should be composite",
            algOid.startsWith(COMPOSITE_OID_PREFIX));
        assertTrue("Public key algorithm should be composite",
            pubKeyAlgOid.startsWith(COMPOSITE_OID_PREFIX));

        // Identify specific algorithm combination
        if (algOid.endsWith(".32")) {
            System.out.println("  Algorithm: MLDSA87-ECDSA-P384-SHA512");
        } else if (algOid.endsWith(".28")) {
            System.out.println("  Algorithm: MLDSA65-ECDSA-P256-SHA512");
        } else {
            System.out.println("  Algorithm: Unknown composite variant");
        }
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
