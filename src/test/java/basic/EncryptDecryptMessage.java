package basic;

import digital_signatures.SignDocumentTest;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

public class EncryptDecryptMessage {

    public static final String KEY_ALIAS = "doc_signer";
    public static final String ENCRYPTED_FILE = "results/encrypted_string.bin";
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

    public String decrypt(Key key, byte[] message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(message);
        return new String(cipherData);
    }

    @Before
    public void setup() throws GeneralSecurityException, IOException {
        initKeyStore(SignDocumentTest.KEY_STORE_FILE_PATH, SignDocumentTest.KEY_STORE_PASSWORD);
    }

    @Test
    public void encryptThenDecryptString() throws GeneralSecurityException, IOException {
        String message = "H1dd3n";
        Key publicKey = getPublicKey(KEY_ALIAS);
        Key privateKey = getPrivateKey(KEY_ALIAS, SignDocumentTest.KEY_STORE_PASSWORD);

        // Encrypt with pub, decrypt with pri
        byte[] encryptedMessage = encrypt(publicKey, message);
        String unencryptedMessage = decrypt(privateKey, encryptedMessage);
        System.out.println(unencryptedMessage);

        // Encrypt with pri, decrypt with pub
        encryptedMessage = encrypt(privateKey, message);
        unencryptedMessage = decrypt(publicKey, encryptedMessage);
        System.out.println(unencryptedMessage);
    }

    @Test
    public void encryptThenDecryptFileContent() throws GeneralSecurityException, IOException {
        String message = "H1dd3n";
        Key publicKey = getPublicKey(KEY_ALIAS);
        Key privateKey = getPrivateKey(KEY_ALIAS, SignDocumentTest.KEY_STORE_PASSWORD);

        // Encrypt with public key
        byte[] encryptedMessage = encrypt(publicKey, message);

        // write byte[] to file
        try (FileOutputStream fos = new FileOutputStream(ENCRYPTED_FILE)) {
            fos.write(encryptedMessage);
        }

        // read byte[] from file
        File file = new File(ENCRYPTED_FILE);
        byte[] fileContent = Files.readAllBytes(file.toPath());

        // decrypt byte[]
        String unencryptedMessage = decrypt(privateKey, fileContent);

        // print original message
        System.out.println(unencryptedMessage);
    }

    @Test
    public void decryptStringFromFileUsingPrivateKey() throws GeneralSecurityException, IOException {
        String inputFile = "results/encrypted_string.bin";
        Key privateKey = getPrivateKey(KEY_ALIAS, SignDocumentTest.KEY_STORE_PASSWORD);
        Path encryptedFilePath = Paths.get("results/encrypted_string.bin");

        byte[] fileBytes = Files.readAllBytes(encryptedFilePath);

        String decryptedMessage = decrypt(privateKey, fileBytes);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}
