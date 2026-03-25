package server;

import crypto.KeyManager;
import handshake.HandshakeManager;
import record.RecordLayer;

import javax.crypto.SecretKey;
import java.security.PrivateKey;

public class Server {

    public static void main(String[] args) throws Exception {

        PrivateKey privateKey = KeyManager.getPrivateKey(
                "keystore/serverkeystore.jks",
                "password",
                "serverkey"
        );

        // Normally received from client
        byte[] encryptedPreMaster = new byte[256];
        byte[] clientRandom = new byte[32];
        byte[] serverRandom = new byte[32];

        SecretKey sessionKey = HandshakeManager.serverHandshake(
                privateKey,
                encryptedPreMaster,
                clientRandom,
                serverRandom
        );

        // Example receive
        byte[] encryptedData = new byte[128];
        byte[] decrypted = RecordLayer.decrypt(encryptedData, sessionKey);

        System.out.println("Received: " + new String(decrypted));
    }
}