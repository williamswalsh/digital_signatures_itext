package versions_gt_5_3_0;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import digital_signatures.SignDocumentTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;

public class SignPdf {

    public static final String ORIGINAL_DOC = "results/new_version_unsigned.pdf";
    public static final String SIGNED_DOC = "results/new_version_signed.pdf";
    public static final String REMOVED_SIGNATURE_DOC = "results/new_signature_removed.pdf";
    public static final String BOUNCY_CASTLE_PROVIDER_CODE = "BC";
    public static final String SIGNATURE_REASON = "Document Certification";
    public static final String SIGNATURE_FIELD_NAME = "williams_signature";
    public static final String SIGNATURE_LOCATION = "Dublin, Ireland";

    public static final String KEY_ALIAS = "doc_signer";
    public static final String ENCRYPTED_FILE = "results/encrypted_string.bin";
    public static final String ORIGINAL_MESSAGE = "H1dd3n";
    public static final String ENCRYPTED_FILE_PATH = "results/encrypted_string.bin";
    protected KeyStore ks;


    public void initKeyStore(String keystore, String ks_pass)
            throws GeneralSecurityException, IOException {
        ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), ks_pass.toCharArray());
    }

    public X509Certificate getCertificate(String alias) throws KeyStoreException {
        return (X509Certificate) ks.getCertificate(alias);
    }

    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        return ks.getCertificateChain(alias);
    }

    public Key getPublicKey(String alias) throws GeneralSecurityException {
        return getCertificate(alias).getPublicKey();
    }

    public PrivateKey getPrivateKey(String alias, String pk_pass) throws GeneralSecurityException {
        return (PrivateKey) ks.getKey(alias, pk_pass.toCharArray());
    }

    public byte[] encrypt(Key key, String message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message.getBytes());
    }

    public byte[] decrypt(Key key, byte[] message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(message);
    }

    @Before
    public void setup() throws GeneralSecurityException, IOException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        initKeyStore(SignDocumentTest.KEY_STORE_FILE_PATH, SignDocumentTest.KEY_STORE_PASSWORD);
    }

    // Results in an Approval Signature
    @Test
    public void signPdfWithDetachedSignature() throws GeneralSecurityException, DocumentException, IOException {
        PrivateKey privateKey = getPrivateKey(KEY_ALIAS, SignDocumentTest.KEY_STORE_PASSWORD);
        Certificate[] certificateChain = getCertificateChain(KEY_ALIAS);
        String digestAlgo = DigestAlgorithms.SHA256;

        new SignPdf().sign(ORIGINAL_DOC, SIGNED_DOC, certificateChain, privateKey, digestAlgo, BOUNCY_CASTLE_PROVIDER_CODE,
                MakeSignature.CryptoStandard.CADES, SIGNATURE_REASON, SIGNATURE_LOCATION);
    }

    @Test
    public void removeSignatureFieldFromDocumentUsingName() throws DocumentException, IOException {
        new SignPdf().removeSignatureFromPdfv4(SIGNED_DOC, REMOVED_SIGNATURE_DOC);
    }

    public void sign(String src, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, MakeSignature.CryptoStandard subFilter, String reason, String location)
            throws GeneralSecurityException, IOException, DocumentException {

        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');

        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);

        // Creating the signature
        // TODO: If uncommented this line blocks signature creation - no errors - overlapping content???
        // appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, SIGNATURE_FIELD_NAME);
        ExternalDigest digest = new BouncyCastleDigest();       // Equivalent to "BC" - KeyStore.getInstance(PKCS_12, "BC");
        ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, provider);
        MakeSignature.signDetached(appearance, digest, signature, chain,
                null, null, null, 0, subFilter);
    }

    /**
     * This method does remove the signature and my basic test document isn't broken
     */
    public void removeSignatureFromPdfv1(String inputFilePath, String outputFilePath) throws DocumentException, IOException {
        PdfReader reader = new PdfReader(inputFilePath);
        PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(outputFilePath));

        AcroFields acroFields = reader.getAcroFields();
        acroFields.removeField(SIGNATURE_FIELD_NAME);
        stamper.setFormFlattening(true);

        stamper.close();
        reader.close();
    }

    /**
     * This method does remove the signature and my basic test document isn't broken
     */
    public void removeSignatureFromPdfv2(String inputFilePath, String outputFilePath) throws DocumentException, IOException {
        PdfReader reader = new PdfReader(inputFilePath);
        PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(outputFilePath));

        AcroFields fields = stamper.getAcroFields();
        fields.setGenerateAppearances(true);            // Display signature widget
        stamper.setFormFlattening(true);

        stamper.close();
        reader.close();
    }

    /**
     * This method does not remove the signature.
     * At least one signature is invalid.
     * There are errors in the formatting of information contained in this signature.
     * SigDict /Contents illegal data
     */
    public void removeSignatureFromPdfv3(String inputFilePath, String outputFilePath) throws DocumentException, IOException {
        PdfReader reader = new PdfReader(inputFilePath);
        PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(outputFilePath));

        AcroFields acroFields = reader.getAcroFields();
        acroFields.removeField(SIGNATURE_FIELD_NAME);
        stamper.getAcroFields().clearSignatureField(SIGNATURE_FIELD_NAME);
        // stamper.setFormFlattening(true);

        stamper.close();
        reader.close();
    }

    /**
     * This method does not remove the signature.
     * At least one signature is invalid.
     * There are errors in the formatting of information contained in this signature.
     * SigDict /Contents illegal data
     */
    public void removeSignatureFromPdfv4(String inputFilePath, String outputFilePath) throws DocumentException, IOException {
        PdfReader reader = new PdfReader(inputFilePath);
        PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(outputFilePath));

        reader.getAcroFields().removeField(SIGNATURE_FIELD_NAME);
        stamper.getAcroFields().clearSignatureField(SIGNATURE_FIELD_NAME);
        stamper.getAcroFields().setGenerateAppearances(true);            // Display signature widget
        // stamper.setFormFlattening(true);

        stamper.close();
        reader.close();
    }
}
