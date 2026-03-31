package handshake;

import java.security.SecureRandom;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import org.junit.jupiter.api.Test;

//TEST CASE TO PROVE HANDSHAKE WORKS
public class HandshakeTest {

    @Test
    public void testSessionKeyMatch() throws Exception {

        //Initialize byte arrays for the pre-master secret and random values used in key derivation
        byte[] preMaster = new byte[48];
        byte[] clientRandom = new byte[32];
        byte[] serverRandom = new byte[32];

        //Fill the arrays with cryptographically strong random data
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(preMaster);
        rand.nextBytes(clientRandom);
        rand.nextBytes(serverRandom);

        //Simulate both the client and server deriving a session key from the same shared secrets
        SecretKey clientKey = HandshakeManager.deriveSessionKey(preMaster, clientRandom, serverRandom);
        SecretKey serverKey = HandshakeManager.deriveSessionKey(preMaster, clientRandom, serverRandom);

        //Verify that both derived keys are identical to ensure the handshake logic is consistent
        assertArrayEquals(clientKey.getEncoded(), serverKey.getEncoded());
    }
}


