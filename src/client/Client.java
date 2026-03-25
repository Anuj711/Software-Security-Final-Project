//Main entry point

package client;

import crypto.KeyManager;
import handshake.ClientHello;
import handshake.ServerHello;
import handshake.HandshakeManager;
import record.RecordLayer;

import javax.crypto.SecretKey;
import java.security.PublicKey;

public class Client {

    public static void main(String[] args) throws Exception {

        // Step 1: load server public key
        PublicKey serverPublicKey = KeyManager.getPublicKey("certs/server.cer");

        // Step 2: hello messages
        ClientHello ch = new ClientHello();
        ServerHello sh = new ServerHello(); // normally received from server

        // Step 3: handshake
        SecretKey sessionKey = HandshakeManager.clientHandshake(
                serverPublicKey,
                ch.clientRandom,
                sh.serverRandom
        );

        // Step 4: send secure message
        String message = "Hello Secure World!";
        byte[] encrypted = RecordLayer.encrypt(message.getBytes(), sessionKey);

        System.out.println("Encrypted sent: " + encrypted.length);
    }
}