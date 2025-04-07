import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Utility class for encryption and decryption using AES.
 */
class CryptoUtils {
    /**
     * Encrypts data using AES encryption.
     */
    public static byte[] encrypt(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    /**
     * Decrypts data using AES encryption.
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }
}
