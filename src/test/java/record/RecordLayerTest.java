package record;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

//TEST CASE TO PROVE ENCRYPTION/DECRYPTION WORKS
public class RecordLayerTest {

    @Test
    public void testEncryptDecrypt() throws Exception {

        //Setup a 128-bit AES key for the encryption/decryption process
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey key = kg.generateKey();

        //Define a test message string
        String message = "Test message";

        //Pass the message through the record layer to encrypt (adds MAC and AES encryption)
        byte[] encrypted = RecordLayer.encrypt(message.getBytes(), key);

        //Decrypt the result (verifies MAC and performs AES decryption)
        byte[] decrypted = RecordLayer.decrypt(encrypted, key);

        //Assert that the final decrypted output matches the original input message
        assertEquals(message, new String(decrypted));
    }
}


