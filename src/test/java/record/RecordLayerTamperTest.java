package record;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

//TEST CASE FOR INTEGRITY CHECK (MAC)
public class RecordLayerTamperTest {

    @Test
    public void testTamperedMessageFails() throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey key = kg.generateKey();

        String message = "Secure Data";

        byte[] encrypted = RecordLayer.encrypt(message.getBytes(), key);

        // Tamper with data
        encrypted[5] ^= 1;

        assertThrows(SecurityException.class, () -> {
            RecordLayer.decrypt(encrypted, key);
        });
    }
}