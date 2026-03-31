package record;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

//TEST CASE TO PROVE ENCRYPTION/DECRYPTION WORKS
public class RecordLayerTest {

    @Test
    public void testEncryptDecrypt() throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey key = kg.generateKey();

        String message = "Test message";

        byte[] encrypted = RecordLayer.encrypt(message.getBytes(), key);
        byte[] decrypted = RecordLayer.decrypt(encrypted, key);

        assertEquals(message, new String(decrypted));
    }
}