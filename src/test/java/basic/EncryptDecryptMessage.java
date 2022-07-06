package basic;

import digital_signatures.SignDocumentTest;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;

public class EncryptDecryptMessage {

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

    public Key getPublicKey(String alias) throws GeneralSecurityException {
        return getCertificate(alias).getPublicKey();
    }

    public Key getPrivateKey(String alias, String pk_pass) throws GeneralSecurityException {
        return ks.getKey(alias, pk_pass.toCharArray());
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
        initKeyStore(SignDocumentTest.KEY_STORE_FILE_PATH, SignDocumentTest.KEY_STORE_PASSWORD);
    }

    @Test
    public void encryptThenDecryptString() throws GeneralSecurityException, IOException {
        String originalMessage = "H1dd3n";
        Key publicKey = getPublicKey(KEY_ALIAS);
        Key privateKey = getPrivateKey(KEY_ALIAS, SignDocumentTest.KEY_STORE_PASSWORD);

        // Encrypt with pub, decrypt with pri
        byte[] encryptedMessage = encrypt(publicKey, originalMessage);
        String unencryptedMessage = new String(decrypt(privateKey, encryptedMessage), Charset.defaultCharset());
        assertEquals(originalMessage, unencryptedMessage);

        // Encrypt with pri, decrypt with pub
        encryptedMessage = encrypt(privateKey, originalMessage);
        unencryptedMessage = new String(decrypt(publicKey, encryptedMessage), Charset.defaultCharset());
        assertEquals(originalMessage, unencryptedMessage);
    }

    @Test
    public void encryptThenDecryptFileContent() throws GeneralSecurityException, IOException {
        Key publicKey = getPublicKey(KEY_ALIAS);
        Key privateKey = getPrivateKey(KEY_ALIAS, SignDocumentTest.KEY_STORE_PASSWORD);

        // Encrypt with public key
        byte[] encryptedMessage = encrypt(publicKey, ORIGINAL_MESSAGE);

        // write byte[] to file
        try (FileOutputStream fos = new FileOutputStream(ENCRYPTED_FILE)) {
            fos.write(encryptedMessage);
        }

        // read byte[] from file
        File file = new File(ENCRYPTED_FILE);
        byte[] fileContent = Files.readAllBytes(file.toPath());

        // decrypt byte[]
        String unencryptedMessage = new String(decrypt(privateKey, fileContent), Charset.defaultCharset());

        // Assert unencrypted message is equal to the original message
        assertEquals(ORIGINAL_MESSAGE, unencryptedMessage);
    }

    @Test
    public void decryptStringFromFileUsingPrivateKey() throws GeneralSecurityException, IOException {
        Key privateKey = getPrivateKey(KEY_ALIAS, SignDocumentTest.KEY_STORE_PASSWORD);
        byte[] fileBytes = Files.readAllBytes(Paths.get(ENCRYPTED_FILE_PATH));

        String decryptedMessage = new String(decrypt(privateKey, fileBytes), Charset.defaultCharset());
        assertEquals(ORIGINAL_MESSAGE, decryptedMessage);
    }
}
