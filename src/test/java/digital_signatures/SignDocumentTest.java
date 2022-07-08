package digital_signatures;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

/**
 * The tests present in this class only work with older versions of iText5 < v5.3.0
 * There has been a change made where setCrypto method of the PdfSignatureAppearance isn't present anymore.
 *
 * A change has been made in iText5 versions >= v5.3.0.
 * The change blocks the use of non-detached signatures.
 * In other words, you must use detached signatures from now on.
 * Detached Signatures Details:
 * - The detached signature option is available to provide everyone with the option of viewing the message without having the public key.
 * - This creates a separate signature file that is used to verify the original message if desired.
 * - In its simplest form, this file contains a hash of the original message and is encrypted with the private key.
 * - Anyone with the public key can open the signature and then compare hashes to verify the integrity of the signed file.
 */
public class SignDocumentTest {
    public static final String ORIGINAL_DOC = "results/unsigned.pdf";
    public static final String SIGNED_DOC = "results/signed.pdf";
    public static final String SIGNED_DOC_2 = "results/signed_2.pdf";
    public static final String FLATTENED_DOC = "results/flattened.pdf";
    public static final String KEY_STORE_FILE_PATH = "encryption/subfolder/keystore.p12";
    public static final String KEY_STORE_PASSWORD = "Password1!";
    public static final String PKCS_12 = "pkcs12";
    public static final String BOUNCY_CASTLE_PROVIDER_CODE = "BC";
    public static final String SIGNATURE_REASON = "Document Certification";
    public static final String SIGNATURE_LOCATION = "Dublin, Ireland";
    public static final String SIGNATURE_FIELD_NAME = "williams_signature";

    @Before
    public void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testSigning() throws IOException, DocumentException, GeneralSecurityException {
        createPdf(ORIGINAL_DOC);
        signPdf(ORIGINAL_DOC, SIGNED_DOC);
    }

    @Test
    public void testSigningAndFlatteningSignature() throws IOException, DocumentException, GeneralSecurityException {
        createPdf(ORIGINAL_DOC);
        signPdf(ORIGINAL_DOC, SIGNED_DOC_2);
        removeSignatureFromPdf(SIGNED_DOC_2, FLATTENED_DOC);
    }

    public void createPdf(String filePath) throws FileNotFoundException, DocumentException {
        Document document = new Document();
        PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(filePath));
        document.open();
        document.add(new Paragraph("Hello World, digital signature style!"));

        PdfFormField signatureField = PdfFormField.createSignature(writer);
        signatureField.setFieldName(SIGNATURE_FIELD_NAME);
        writer.addAnnotation(signatureField);
        document.close();
    }

    public void signPdf(String inputPdf, String outputPdf)
            throws IOException, DocumentException, GeneralSecurityException {

        // For PKCS#12 - the keystore password is the same as the key password
        String keyPassword = KEY_STORE_PASSWORD;

        // Getting key
        KeyStore ks = KeyStore.getInstance(PKCS_12, BOUNCY_CASTLE_PROVIDER_CODE);
        ks.load(new FileInputStream(KEY_STORE_FILE_PATH), KEY_STORE_PASSWORD.toCharArray());
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, keyPassword.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);

        // Signing
        PdfReader reader = new PdfReader(inputPdf);
        PdfStamper stamper = PdfStamper.createSignature(reader, new FileOutputStream(outputPdf), '\0');
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(SIGNATURE_REASON);
        appearance.setLocation(SIGNATURE_LOCATION);
        // appearance.setCrypto(pk, chain, null, PdfSignatureAppearance.WINCER_SIGNED); // OLD
        appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_FORM_FILLING);
        stamper.close();
    }

    public void removeSignatureFromPdfByFlattening(String inputFilePath, String outputFilePath) throws DocumentException, IOException {
        PdfReader reader = new PdfReader(inputFilePath);
        PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(outputFilePath));

        // stamper.getAcroFields().setGenerateAppearances(true);
        stamper.setFormFlattening(true);
        stamper.close();
        reader.close();
    }

    public void removeSignatureFromPdf(String inputFilePath, String outputFilePath) throws DocumentException, IOException {
        PdfReader reader = new PdfReader(inputFilePath);
        PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(outputFilePath));

        stamper.getAcroFields().clearSignatureField(SIGNATURE_FIELD_NAME);
        // stamper.setFormFlattening(true);
        stamper.close();
        reader.close();
    }
}


// // NOTE: This doesn't remove the signature from the document
// public void removeSignature(String inputFilePath, String outputFilePath) throws DocumentException, IOException {
//     PdfReader reader = new PdfReader(inputFilePath);
//     OutputStream outputFileStream = new FileOutputStream(outputFilePath);
//
//     AcroFields acroFields = reader.getAcroFields();
//     acroFields.removeField(SIGNATURE_FIELD_NAME);
//     PdfStamper stamper = new PdfStamper(reader, outputFileStream);
//     stamper.close();
//     reader.close();
// }

// v5.5.5
// PdfReader reader = new PdfReader(new FileInputStream(file));
// FileOutputStream fout = new FileOutputStream(new File(targetDir, fileName));
// PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0');
//
// PdfSignatureAppearance sap = stp.getSignatureAppearance();
// sap.setReason(reason);
// sap.setLocation("Pleber-Christ");
//
// ExternalDigest digest = new BouncyCastleDigest();
// BouncyCastleProvider provider = new BouncyCastleProvider();
// ExternalSignature signature = new PrivateKeySignature(key, DigestAlgorithms.SHA256, provider.getName());
// MakeSignature.signDetached(sap, digest, signature, chain,   null, null, null, 0, CryptoStandard.CMS);
