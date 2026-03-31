//AES (Advanced Encryption Standard) Encryption -- Session Encryption

package crypto;

import javax.crypto.*;

public class AESUtil {

    //Generates a 128-bit AES secret key for encryption and decryption
    public static SecretKey generateKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        return kg.generateKey();
    }
    //Encrypts the provided byte array using the AES algorithm and secret key
    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    //Decrypts the encrypted byte array back to its original form using the secret key
    public static byte[] decrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }
}