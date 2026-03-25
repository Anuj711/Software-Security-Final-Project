//Main handshake logic to connect the client and server

package handshake;

import crypto.RSAUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

public class HandshakeManager {

    public static SecretKey clientHandshake(PublicKey serverPublicKey,
                                            byte[] clientRandom,
                                            byte[] serverRandom) throws Exception {

        // Step 1: generate pre-master secret
        byte[] preMaster = new byte[48];
        new SecureRandom().nextBytes(preMaster);

        // Step 2: encrypt with server public key
        byte[] encrypted = RSAUtil.encrypt(preMaster, serverPublicKey);

        // (send encrypted to server in real app)

        // Step 3: derive session key
        return deriveSessionKey(preMaster, clientRandom, serverRandom);
    }

    public static SecretKey serverHandshake(PrivateKey privateKey,
                                            byte[] encryptedPreMaster,
                                            byte[] clientRandom,
                                            byte[] serverRandom) throws Exception {

        byte[] preMaster = RSAUtil.decrypt(encryptedPreMaster, privateKey);

        return deriveSessionKey(preMaster, clientRandom, serverRandom);
    }

    private static SecretKey deriveSessionKey(byte[] preMaster,
                                              byte[] clientRandom,
                                              byte[] serverRandom) throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(preMaster);
        md.update(clientRandom);
        md.update(serverRandom);

        byte[] keyBytes = md.digest();

        return new SecretKeySpec(Arrays.copyOf(keyBytes, 16), "AES");
    }
}