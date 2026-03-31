package server;

import crypto.KeyManager;
import crypto.RSAUtil;
import handshake.HandshakeManager;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import javax.crypto.SecretKey;
import record.RecordLayer;

/**
 * SERVER:
 * - Waits for client connection
 * - Performs SSL handshake
 * - Receives encrypted message from client and decrypts secure message
 */
public class Server {

    public static void main(String[] args) throws Exception {

        // Start server on port 5000
        ServerSocket serverSocket = new ServerSocket(5000);
        System.out.println("Server started...");

        // Wait for client
        Socket socket = serverSocket.accept();
        System.out.println("Client connected");

        // Streams for communication
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // Load server's private key (for decrypting pre-master)
        PrivateKey privateKey = KeyManager.getPrivateKey(
                "keystore/serverkeystore.jks",
                "password",
                "serverkey"
        );

        // =========================
        // ===== HANDSHAKE =========
        // =========================

        // Step 1: Receive client random
        byte[] clientRandom = new byte[32];
        in.readFully(clientRandom);

        // Step 2: Generate server random
        byte[] serverRandom = new byte[32];
        new java.security.SecureRandom().nextBytes(serverRandom);

        // Send server random back to client
        out.write(serverRandom);

        // Step 3: Receive encrypted pre-master
        int length = in.readInt();
        byte[] encryptedPreMaster = new byte[length];
        in.readFully(encryptedPreMaster);

        // Decrypt pre-master using server's private key
        byte[] preMaster = RSAUtil.decrypt(encryptedPreMaster, privateKey);

        // Step 4: Derive session key (same formula as client)
        SecretKey sessionKey = HandshakeManager.deriveSessionKey(
                preMaster,
                clientRandom,
                serverRandom
        );

        System.out.println("Handshake complete (Server)");

        // ===== RECORD LAYER ======

        // Receive encrypted message
        int msgLength = in.readInt();
        byte[] encryptedMessage = new byte[msgLength];
        in.readFully(encryptedMessage);

        // Decrypt and verify integrity
        byte[] decryptedMessage = RecordLayer.decrypt(encryptedMessage, sessionKey);

        System.out.println("Received secure message: " + new String(decryptedMessage));

        // Close connections
        socket.close();
        serverSocket.close();
    }
}