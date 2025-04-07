import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.SealedObject;

/**
 * Server class that handles the Diffie-Hellman key exchange, receives encrypted data, and decrypts it.
 */
class Server {
    public static void main(String[] args) throws Exception {
        // Step 1: Start the server and wait for a client connection
        ServerSocket serverSocket = new ServerSocket(5050);
        System.out.println("Server started. Waiting for client...");
        System.out.println("Server is listening on port 5050...");

        // Step 2: Accept the client connection
        Socket clientSocket = serverSocket.accept();
        System.out.println("Client connected.");

        // Step 3: Setup input and output streams for communication
        ObjectInputStream input = new ObjectInputStream(clientSocket.getInputStream());
        ObjectOutputStream output = new ObjectOutputStream(clientSocket.getOutputStream());

        // Step 4: Generate the server's Diffie-Hellman key pair
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Step 5: Send the server's public key to the client
        output.writeObject(keyPair.getPublic());
        output.flush();

        // Step 6: Receive the client's public key
        PublicKey clientPublicKey = (PublicKey) input.readObject();

        // Step 7: Generate the shared secret key using the client's public key
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(clientPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

        System.out.println("Shared secret key established.");

        // Step 8: Authenticate the client
        String clientChallenge = "serverChallenge123"; // Server's challenge
        output.writeObject(clientChallenge); // Send challenge to client
        output.flush();
        String clientResponse = (String) input.readObject(); // Receive client's response
        boolean clientAuthenticated = CryptoUtils.hash(clientChallenge + "clientSecret").equals(clientResponse);
        output.writeObject(clientAuthenticated); // Send authentication result to client
        output.flush();
        if (!clientAuthenticated) {
            System.out.println("Client authentication failed.");
            clientSocket.close();
            serverSocket.close();
            return;
        }
        System.out.println("Client authenticated.");

        // Step 9: Authenticate the server
        String serverChallenge = (String) input.readObject(); // Receive challenge from client
        String serverResponse = CryptoUtils.hash(serverChallenge + "serverSecret"); // Hash with server secret
        output.writeObject(serverResponse); // Send response to client
        output.flush();
        boolean serverAuthenticated = (boolean) input.readObject(); // Receive client authentication result
        if (!serverAuthenticated) {
            System.out.println("Server authentication failed.");
            clientSocket.close();
            serverSocket.close();
            return;
        }
        System.out.println("Server authenticated.");

        // Step 10: Receive the encrypted object from the client
        SealedObject sealedObject = (SealedObject) input.readObject();

        // Step 11: Decrypt the object using the shared secret key
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        SecureData receivedData = (SecureData) sealedObject.getObject(cipher);

        // Step 12: Print the decrypted object details
        System.out.println("Received decrypted data: " + receivedData);

        // Step 13: Close the connection
        clientSocket.close();
        serverSocket.close();
    }
}

