package pki_encryption;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.*;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class PkiEncryption {
    public static final String INPUT_FILE_PATH = "results/hello.pdf";
    public static final String OUTPUT_FILE_PATH = "results/hello_pki_encrypted.pdf";
    public static final String CERT_FILE_PATH = "/Users/will/code/itext/itext_in_action/encryption/foobar_2.cer";

    // @Test
    // public void encryptPdfUsingPublicKey() throws FileNotFoundException, CertificateException, DocumentException {
    //     createEncryptedPdf(CERT_FILE_PATH, OUTPUT_FILE_PATH);
    // }

    @Test
    public void encryptDoc() throws IOException, DocumentException, CertificateException {
        PdfReader reader = new PdfReader(INPUT_FILE_PATH);
        PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(OUTPUT_FILE_PATH));
        Certificate cert = readCertificateFromFile("encryption/foobar_2.cer");
        stamper.setEncryption(new Certificate[]{cert},
                new int[]{PdfWriter.ALLOW_PRINTING}, PdfWriter.ENCRYPTION_AES_128);
        stamper.close();
    }

    private X509Certificate readCertificateFromFile(String filePath)
            throws FileNotFoundException, CertificateException {
        FileInputStream certFileInputStream = new FileInputStream(filePath);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(certFileInputStream);
        return cert;
    }

    // private void createEncryptedPdf(String certFilePath, String outputFilePath)
    //         throws FileNotFoundException, CertificateException, DocumentException {
    //     Document document = new Document();
    //     PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(outputFilePath));
    //     Certificate cert = readCertificateFromFile(certFilePath);
    //
    //     writer.setEncryption(
    //             new Certificate[] { cert },
    //             new int[] {PdfWriter.ALLOW_PRINTING},
    //             PdfWriter.STANDARD_ENCRYPTION_128);
    //     // TODO
    //     //  ExceptionConverter: java.security.NoSuchAlgorithmException: 1.2.840.113549.3.2 AlgorithmParameterGenerator not available
    //     // 	at java.base/sun.security.jca.GetInstance.getInstance(GetInstance.java:159)
    //     // 	at java.base/java.security.Security.getImpl(Security.java:701)
    //     // 	at java.base/java.security.AlgorithmParameterGenerator.getInstance(AlgorithmParameterGenerator.java:177)
    //     // 	at com.itextpdf.text.pdf.PdfPublicKeySecurityHandler.createDERForRecipient(PdfPublicKeySecurityHandler.java:233)
    //     // 	at com.itextpdf.text.pdf.PdfPublicKeySecurityHandler.getEncodedRecipient(PdfPublicKeySecurityHandler.java:194)
    //     // 	at com.itextpdf.text.pdf.PdfEncryption.getEncryptionDictionary(PdfEncryption.java:645)
    //     // 	at com.itextpdf.text.pdf.PdfWriter.setEncryption(PdfWriter.java:2135)
    //     // 	at pki_encryption.PkiEncryption.createEncryptedPdf(PkiEncryption.java:40)
    //
    //     document.open();
    //
    //     // Messy: Content mixed in with encryption details
    //     document.add(new Paragraph("GPS: 52.46060906351363, -9.750502764491772"));
    //     document.close();
    // }
}
