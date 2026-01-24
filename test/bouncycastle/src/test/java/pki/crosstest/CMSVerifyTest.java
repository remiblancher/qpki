package pki.crosstest;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Cross-test: Verify CMS SignedData with BouncyCastle.
 *
 * This test validates that our CMS signatures are correctly formatted
 * and can be verified by an independent implementation.
 *
 * Tests all algorithm types:
 * - Classical ECDSA
 * - PQC ML-DSA-87 (FIPS 204)
 * - PQC SLH-DSA (FIPS 205)
 * - Catalyst Hybrid (ECDSA + ML-DSA)
 * - Composite Hybrid (IETF draft-13)
 */
public class CMSVerifyTest {

    private static final String FIXTURES = "../fixtures";

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // =========================================================================
    // Classical ECDSA
    // =========================================================================

    @Test
    @DisplayName("[TC-XBC-CMS-EC] Verify: CMS Classical ECDSA (attached)")
    public void testCrossCompat_Verify_CMS_Classical_Attached() throws Exception {
        Path cmsFile = Paths.get(FIXTURES, "classical/ecdsa/cms-attached.p7s");
        assumeTrue(Files.exists(cmsFile), "Classical CMS attached fixture not generated - run generate_qpki_fixtures.sh");

        CMSSignedData signedData = new CMSSignedData(Files.readAllBytes(cmsFile));
        assertNotNull(signedData, "CMS should parse");

        // Verify content is attached
        assertNotNull(signedData.getSignedContent(), "Content should be attached");

        // Verify signature
        verifyCMSSignature(signedData, "Classical ECDSA");
    }

    @Test
    @DisplayName("[TC-XBC-CMS-EC] Verify: CMS Classical ECDSA (detached)")
    public void testCrossCompat_Verify_CMS_Classical_Detached() throws Exception {
        Path cmsFile = Paths.get(FIXTURES, "classical/ecdsa/cms-detached.p7s");
        Path dataFile = Paths.get(FIXTURES, "testdata.txt");
        assumeTrue(Files.exists(cmsFile), "Classical CMS detached fixture not generated - run generate_qpki_fixtures.sh");
        assumeTrue(Files.exists(dataFile), "Test data file not generated - run generate_qpki_fixtures.sh");

        byte[] content = Files.readAllBytes(dataFile);
        CMSSignedData signedData = new CMSSignedData(
            new org.bouncycastle.cms.CMSProcessableByteArray(content),
            Files.readAllBytes(cmsFile)
        );
        assertNotNull(signedData, "CMS should parse");

        // Verify signature
        verifyCMSSignature(signedData, "Classical ECDSA (detached)");
    }

    // =========================================================================
    // PQC ML-DSA-87
    // =========================================================================

    @Test
    @DisplayName("[TC-XBC-CMS-ML] Verify: CMS ML-DSA-87 (attached)")
    public void testCrossCompat_Verify_CMS_MLDSA_Attached() throws Exception {
        Path cmsFile = Paths.get(FIXTURES, "pqc/mldsa/cms-attached.p7s");
        assumeTrue(Files.exists(cmsFile), "ML-DSA CMS attached fixture not generated - run generate_qpki_fixtures.sh");

        CMSSignedData signedData = new CMSSignedData(Files.readAllBytes(cmsFile));
        assertNotNull(signedData, "CMS should parse");

        // Verify content is attached
        assertNotNull(signedData.getSignedContent(), "Content should be attached");

        // Verify signature
        verifyCMSSignature(signedData, "ML-DSA-87");
    }

    @Test
    @DisplayName("[TC-XBC-CMS-ML] Verify: CMS ML-DSA-87 (detached)")
    public void testCrossCompat_Verify_CMS_MLDSA_Detached() throws Exception {
        Path cmsFile = Paths.get(FIXTURES, "pqc/mldsa/cms-detached.p7s");
        Path dataFile = Paths.get(FIXTURES, "testdata.txt");
        assumeTrue(Files.exists(cmsFile), "ML-DSA CMS detached fixture not generated - run generate_qpki_fixtures.sh");
        assumeTrue(Files.exists(dataFile), "Test data file not generated - run generate_qpki_fixtures.sh");

        byte[] content = Files.readAllBytes(dataFile);
        CMSSignedData signedData = new CMSSignedData(
            new org.bouncycastle.cms.CMSProcessableByteArray(content),
            Files.readAllBytes(cmsFile)
        );
        assertNotNull(signedData, "CMS should parse");

        // Verify signature
        verifyCMSSignature(signedData, "ML-DSA-87 (detached)");
    }

    // =========================================================================
    // PQC SLH-DSA
    // =========================================================================

    @Test
    @DisplayName("[TC-XBC-CMS-SLH] Verify: CMS SLH-DSA (attached)")
    public void testCrossCompat_Verify_CMS_SLHDSA_Attached() throws Exception {
        Path cmsFile = Paths.get(FIXTURES, "pqc/slhdsa/cms-attached.p7s");
        assumeTrue(Files.exists(cmsFile), "SLH-DSA CMS attached fixture not generated - run generate_qpki_fixtures.sh");

        CMSSignedData signedData = new CMSSignedData(Files.readAllBytes(cmsFile));
        assertNotNull(signedData, "CMS should parse");

        // Verify content is attached
        assertNotNull(signedData.getSignedContent(), "Content should be attached");

        // Verify signature
        verifyCMSSignature(signedData, "SLH-DSA");
    }

    @Test
    @DisplayName("[TC-XBC-CMS-SLH] Verify: CMS SLH-DSA (detached)")
    public void testCrossCompat_Verify_CMS_SLHDSA_Detached() throws Exception {
        Path cmsFile = Paths.get(FIXTURES, "pqc/slhdsa/cms-detached.p7s");
        Path dataFile = Paths.get(FIXTURES, "testdata.txt");
        assumeTrue(Files.exists(cmsFile), "SLH-DSA CMS detached fixture not generated - run generate_qpki_fixtures.sh");
        assumeTrue(Files.exists(dataFile), "Test data file not generated - run generate_qpki_fixtures.sh");

        byte[] content = Files.readAllBytes(dataFile);
        CMSSignedData signedData = new CMSSignedData(
            new org.bouncycastle.cms.CMSProcessableByteArray(content),
            Files.readAllBytes(cmsFile)
        );
        assertNotNull(signedData, "CMS should parse");

        // Verify signature
        verifyCMSSignature(signedData, "SLH-DSA (detached)");
    }

    // =========================================================================
    // Catalyst Hybrid (ECDSA + ML-DSA)
    // =========================================================================

    @Test
    @DisplayName("[TC-XBC-CMS-CAT] Verify: CMS Catalyst Hybrid (attached)")
    public void testCrossCompat_Verify_CMS_Catalyst_Attached() throws Exception {
        Path cmsFile = Paths.get(FIXTURES, "catalyst/cms-attached.p7s");
        assumeTrue(Files.exists(cmsFile), "Catalyst CMS attached fixture not generated - run generate_qpki_fixtures.sh");

        CMSSignedData signedData = new CMSSignedData(Files.readAllBytes(cmsFile));
        assertNotNull(signedData, "CMS should parse");

        // Verify content is attached
        assertNotNull(signedData.getSignedContent(), "Content should be attached");

        // Catalyst uses classical signature in CMS
        verifyCMSSignature(signedData, "Catalyst Hybrid");
    }

    @Test
    @DisplayName("[TC-XBC-CMS-CAT] Verify: CMS Catalyst Hybrid (detached)")
    public void testCrossCompat_Verify_CMS_Catalyst_Detached() throws Exception {
        Path cmsFile = Paths.get(FIXTURES, "catalyst/cms-detached.p7s");
        Path dataFile = Paths.get(FIXTURES, "testdata.txt");
        assertTrue(Files.exists(cmsFile), "Catalyst CMS detached fixture must exist");
        assertTrue(Files.exists(dataFile), "Test data file must exist");

        byte[] content = Files.readAllBytes(dataFile);
        CMSSignedData signedData = new CMSSignedData(
            new org.bouncycastle.cms.CMSProcessableByteArray(content),
            Files.readAllBytes(cmsFile)
        );
        assertNotNull(signedData, "CMS should parse");

        // Catalyst uses classical signature in CMS
        verifyCMSSignature(signedData, "Catalyst Hybrid (detached)");
    }

    // =========================================================================
    // Composite Hybrid (IETF draft-13)
    // =========================================================================

    @Test
    @Disabled("BC 1.83 uses Composite draft-07, we use IETF draft-13")
    @DisplayName("[TC-XBC-CMS-COMP] Verify: CMS Composite Hybrid (attached)")
    public void testCrossCompat_Verify_CMS_Composite_Attached() throws Exception {
        Path cmsFile = Paths.get(FIXTURES, "composite/cms-attached.p7s");
        assertTrue(Files.exists(cmsFile), "Composite CMS attached fixture must exist");

        CMSSignedData signedData = new CMSSignedData(Files.readAllBytes(cmsFile));
        assertNotNull(signedData, "CMS should parse");

        // Verify content is attached
        assertNotNull(signedData.getSignedContent(), "Content should be attached");

        // Verify signature
        verifyCMSSignature(signedData, "Composite Hybrid");
    }

    @Test
    @Disabled("BC 1.83 uses Composite draft-07, we use IETF draft-13")
    @DisplayName("[TC-XBC-CMS-COMP] Verify: CMS Composite Hybrid (detached)")
    public void testCrossCompat_Verify_CMS_Composite_Detached() throws Exception {
        Path cmsFile = Paths.get(FIXTURES, "composite/cms-detached.p7s");
        Path dataFile = Paths.get(FIXTURES, "testdata.txt");
        assertTrue(Files.exists(cmsFile), "Composite CMS detached fixture must exist");
        assertTrue(Files.exists(dataFile), "Test data file must exist");

        byte[] content = Files.readAllBytes(dataFile);
        CMSSignedData signedData = new CMSSignedData(
            new org.bouncycastle.cms.CMSProcessableByteArray(content),
            Files.readAllBytes(cmsFile)
        );
        assertNotNull(signedData, "CMS should parse");

        // Verify signature
        verifyCMSSignature(signedData, "Composite Hybrid (detached)");
    }

    @Test
    @DisplayName("[TC-XBC-CMS-COMP] Parse: CMS Composite Structure")
    public void testCrossCompat_Parse_CMS_Composite() throws Exception {
        Path cmsFile = Paths.get(FIXTURES, "composite/cms-attached.p7s");
        assumeTrue(Files.exists(cmsFile), "Composite CMS fixture not generated");

        CMSSignedData signedData = new CMSSignedData(Files.readAllBytes(cmsFile));
        assertNotNull(signedData, "CMS should parse");
        assertNotNull(signedData.getSignedContent(), "Content should be attached");

        SignerInformationStore signers = signedData.getSignerInfos();
        assertFalse(signers.getSigners().isEmpty(), "Should have signers");

        SignerInformation signer = signers.getSigners().iterator().next();
        String sigAlgOid = signer.getEncryptionAlgOID();

        System.out.println("Composite CMS Structure: PARSED");
        System.out.println("  Signature Algorithm OID: " + sigAlgOid);
        System.out.println("  Note: Signature verification skipped (BC draft-07 vs QPKI draft-13)");
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    @SuppressWarnings("unchecked")
    private void verifyCMSSignature(CMSSignedData signedData, String algName) throws Exception {
        SignerInformationStore signers = signedData.getSignerInfos();
        assertFalse(signers.getSigners().isEmpty(), "Should have at least one signer");

        SignerInformation signer = signers.getSigners().iterator().next();
        assertNotNull(signer, "Signer info should exist");

        // Print signature algorithm
        String sigAlgOid = signer.getEncryptionAlgOID();
        System.out.println(algName + " Signature Algorithm OID: " + sigAlgOid);

        // Get certificates
        Store<X509CertificateHolder> certStore = signedData.getCertificates();
        Collection<X509CertificateHolder> certs = certStore.getMatches(signer.getSID());
        assertFalse(certs.isEmpty(), "Signer certificate should be included");

        X509CertificateHolder cert = certs.iterator().next();
        System.out.println(algName + " Signer: " + cert.getSubject());

        // Build verifier and verify
        SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
            .setProvider("BC")
            .build(cert);

        assertTrue(signer.verify(verifier), algName + " signature verification must succeed");
        System.out.println(algName + " Signature: VERIFIED");
    }
}
