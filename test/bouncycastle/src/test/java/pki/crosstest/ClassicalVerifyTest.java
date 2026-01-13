package pki.crosstest;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cross-test: Verify Classical (ECDSA) certificates with BouncyCastle.
 *
 * This test validates that our ECDSA certificates are correctly formatted
 * and can be verified by an independent implementation.
 */
public class ClassicalVerifyTest {

    private static final String FIXTURES = "../fixtures/classical";

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @DisplayName("[TC-XBC-CERT-EC] Verify: Classical ECDSA CA Signature")
    public void testCrossCompat_Verify_ClassicalECDSACA() throws Exception {
        // Load CA cert
        X509Certificate caCert = loadCert(FIXTURES + "/ca/ca.crt");
        assertNotNull(caCert, "CA certificate should load");

        // Verify self-signed
        X509CertificateHolder holder = new X509CertificateHolder(caCert.getEncoded());
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue(holder.isSignatureValid(verifier),
            "Classical CA signature should verify");

        // Check algorithm OID (ECDSA with SHA-256 or SHA-384)
        String algOid = holder.getSignatureAlgorithm().getAlgorithm().getId();
        System.out.println("Classical CA Signature Algorithm OID: " + algOid);
        assertTrue(algOid.startsWith("1.2.840.10045.4.3"),
            "Should be ECDSA OID"); // ecdsa-with-SHA*
    }

    @Test
    @DisplayName("[TC-XBC-CERT-EC] Verify: Classical ECDSA End-Entity Signature")
    public void testCrossCompat_Verify_ClassicalECDSAEndEntity() throws Exception {
        X509Certificate caCert = loadCert(FIXTURES + "/ca/ca.crt");
        String eeCertPath = findCredentialCert(FIXTURES + "/ca/credentials");

        if (eeCertPath == null) {
            System.out.println("No credential certificate found, skipping EE test");
            return;
        }

        X509Certificate eeCert = loadCert(eeCertPath);
        assertNotNull(eeCert, "EE certificate should load");

        // Verify EE cert signed by CA
        X509CertificateHolder holder = new X509CertificateHolder(eeCert.getEncoded());
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC")
            .build(caCert.getPublicKey());

        assertTrue(holder.isSignatureValid(verifier),
            "Classical EE signature should verify");

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
