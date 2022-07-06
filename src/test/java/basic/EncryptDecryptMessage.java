package basic;

import digital_signatures.SignDocumentTest;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;

public class EncryptDecryptMessage {

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
        byte[] cipherData = cipher.doFinal(message.getBytes());
        return cipherData;
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
    public void encryptString() throws GeneralSecurityException {
        String message = "Top Secret";
        Key publicKey = getPublicKey("doc_signer");
        byte[] encryptedMessage = encrypt(publicKey, message);
        System.out.println(String.format("%X", new BigInteger(1, encryptedMessage)));
    }
}
