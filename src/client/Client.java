package client;

import crypto.KeyManager;
import crypto.RSAUtil;
import handshake.HandshakeManager;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import record.RecordLayer;

/**
 * CLIENT:
 * - Initiates connection to server
 * - Performs SSL handshake
 * - Sends encrypted message using record layer
 */

public class Client {

    public static void main(String[] args) throws Exception {

        // Connect to server
        Socket socket = new Socket("localhost", 5000);
        System.out.println("Connected to server");

        // Streams for communication
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // Load server's public key (from certificate)
        PublicKey serverPublicKey = KeyManager.getPublicKey("certs/server.cer");

        // ===== HANDSHAKE =========

        // Step 1: Generate client random
        byte[] clientRandom = new byte[32];
        new SecureRandom().nextBytes(clientRandom);

        // Send client random to server
        out.write(clientRandom);

        // Step 2: Receive server random
        byte[] serverRandom = new byte[32];
        in.readFully(serverRandom);

        // Step 3: Generate pre-master secret (ONLY ON CLIENT)
        byte[] preMaster = new byte[48];
        new SecureRandom().nextBytes(preMaster);

        // Encrypt pre-master with server's public key
        byte[] encryptedPreMaster = RSAUtil.encrypt(preMaster, serverPublicKey);

        // Send encrypted pre-master to server
        out.writeInt(encryptedPreMaster.length);
        out.write(encryptedPreMaster);

        // Step 4: Derive session key (must match server)
        SecretKey sessionKey = HandshakeManager.deriveSessionKey(
                preMaster,
                clientRandom,
                serverRandom
        );

        System.out.println("Handshake complete (Client)");

        // ===== RECORD LAYER ======

        // Prepare message
        String message = "Hello from client!";

        // Encrypt message using record layer (AES + MAC)
        byte[] encryptedMessage = RecordLayer.encrypt(message.getBytes(), sessionKey);

        // Send encrypted message
        out.writeInt(encryptedMessage.length);
        out.write(encryptedMessage);

        System.out.println("Encrypted message sent");

        // Close connection
        socket.close();
    }
}