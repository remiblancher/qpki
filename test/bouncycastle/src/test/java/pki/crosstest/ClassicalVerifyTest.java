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
 * Cross-test: Verify Classical (ECDSA) certificates with BouncyCastle.
 *
 * This test validates that our ECDSA certificates are correctly formatted
 * and can be verified by an independent implementation.
 */
public class ClassicalVerifyTest {

    private static final String FIXTURES = "../fixtures/classical";

    @BeforeClass
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testClassicalCASignature() throws Exception {
        // Load CA cert
        X509Certificate caCert = loadCert(FIXTURES + "/ca/ca.crt");
        assertNotNull("CA certificate should load", caCert);

        // Verify self-signed
        X509CertificateHolder holder = new X509CertificateHolder(caCert.getEncoded());
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue("Classical CA signature should verify",
            holder.isSignatureValid(verifier));

        // Check algorithm OID (ECDSA with SHA-256 or SHA-384)
        String algOid = holder.getSignatureAlgorithm().getAlgorithm().getId();
        System.out.println("Classical CA Signature Algorithm OID: " + algOid);
        assertTrue("Should be ECDSA OID",
            algOid.startsWith("1.2.840.10045.4.3")); // ecdsa-with-SHA*
    }

    @Test
    public void testClassicalEndEntitySignature() throws Exception {
        X509Certificate caCert = loadCert(FIXTURES + "/ca/ca.crt");
        String eeCertPath = findBundleCert(FIXTURES + "/ca/bundles");

        if (eeCertPath == null) {
            System.out.println("No bundle certificate found, skipping EE test");
            return;
        }

        X509Certificate eeCert = loadCert(eeCertPath);
        assertNotNull("EE certificate should load", eeCert);

        // Verify EE cert signed by CA
        X509CertificateHolder holder = new X509CertificateHolder(eeCert.getEncoded());
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue("Classical EE signature should verify",
            holder.isSignatureValid(verifier));

        System.out.println("Classical EE Subject: " + eeCert.getSubjectX500Principal());
    }

    private X509Certificate loadCert(String path) throws Exception {
        File file = new File(path);
        if (!file.exists()) {
            throw new RuntimeException("Certificate file not found: " + path);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        try (FileInputStream fis = new FileInputStream(file)) {
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
