package message_digest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.Security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

public class MessageDigestTest {

    // Add BouncyCastle provider
    public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    static {
        Security.addProvider(PROVIDER);
    }

    /**
     * This test method hashes a stored String, using the SHA-256 algorithm.
     * I then formats the result into hexadecimal and displays the result.
     *
     * @throws NoSuchAlgorithmException MessageDigest.getInstance(..) will throw this exception if the hashing algo code is not recognized
     */
    @Test
    public void Sha256HashString() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        // Hashing Algorithms: "MD5","SHA-1","SHA-224","SHA-256","SHA-384","SHA-512","RIPEMD128","RIPEMD160","RIPEMD256"
        String text = "Text to hash, cryptographically.";
        md.update(text.getBytes(StandardCharsets.UTF_8));
        byte[] digest = md.digest();

        // Display digest in HEX format - 64 characters
        // %64X -> X -> hexadecimal
        // 64   -> 64 bits right-justified
        // 0    -> prefixed with zer0's
        System.out.println(String.format("%0100X", new BigInteger(1, digest)));
        System.out.println(String.format("%64X", new BigInteger(1, digest)));
        System.out.println(String.format("%4X", new BigInteger(1, digest)));
        System.out.println(String.format("%6X", new BigInteger(1, digest)));
        System.out.println(String.format("%X", new BigInteger(1, digest)));

        // Can add delimiters "|...|" to format string
        // -## means left-justify
        // ## must be greater than the String length - here its 64 chars so 100 works :-)
        System.out.println(String.format("|%-100x|", new BigInteger(1, digest)));
        // ## means right-justify
        System.out.println(String.format("|%100x|", new BigInteger(1, digest)));

        assertEquals("f56c3a71b29e28ce7bc8f2f3f1ede0f89a40b25a8857b2bc25023a40a7391fb8",
                String.format("%1$x", new BigInteger(1, digest), "Unused argument"));
        assertNotSame("f56c3a71b29e28ce7bc8f2f3f1ede0f89a40b25a8857b2bc25023a40a7391fb8",
                String.format("%1$100x", new BigInteger(1, digest), "Unused argument"));
    }

    @Test
    public void printAvailableMessageDigestAlgoritmsFromJdk() {
        Security.getAlgorithms("MessageDigest").forEach(System.out::println);
    }

    @Test
    public void hashUsingBouncyCastleSha256() throws NoSuchAlgorithmException {
        String plainString = "Plaintext Secret";

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
        byte[] digest = messageDigest.digest(plainString.getBytes());
        System.out.println(String.format("%X", new BigInteger(1, digest)));
        // Much longer hash
        // C7929539F9B31A7210886F4D9FC8974039808CAEC701BD5ED455039E3431A9D4FECB6E872B1DF1B5EB1955835C1975A447C07B820F78316DD593A1FD5125E271
    }

}
