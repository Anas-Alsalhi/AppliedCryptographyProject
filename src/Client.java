import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.SealedObject;


/**
 * Client class that initiates a connection, performs key exchange, encrypts data, and sends it.
 */
class Client {
    public static void main(String[] args) throws Exception {
        // Step 1: Connect to the server
        Socket socket = new Socket("localhost", 5050);
        System.out.println("Client attempting to connect to localhost:5050...");
        System.out.println("Connected to server.");

        // Step 2: Setup input and output streams for communication
        ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

        // Step 3: Receive the server's public key for Diffie-Hellman key exchange
        PublicKey serverPublicKey = (PublicKey) input.readObject();

        // Step 4: Generate the client's Diffie-Hellman key pair
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(((DHPublicKey) serverPublicKey).getParams());
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Step 5: Send the client's public key to the server
        output.writeObject(keyPair.getPublic());
        output.flush();

        // Step 6: Generate the shared secret key using the server's public key
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

        // Step 7: Authenticate the server
        String serverChallenge = (String) input.readObject(); // Receive challenge from server
        String serverResponse = CryptoUtils.hash(serverChallenge + "clientSecret"); // Hash with client secret
        output.writeObject(serverResponse); // Send response to server
        output.flush();
        boolean serverAuthenticated = (boolean) input.readObject(); // Receive server authentication result
        if (!serverAuthenticated) {
            System.out.println("Server authentication failed.");
            socket.close();
            return;
        }
        System.out.println("Server authenticated.");

        // Step 8: Authenticate the client
        String clientChallenge = "clientChallenge123"; // Client's challenge
        output.writeObject(clientChallenge); // Send challenge to server
        output.flush();
        String clientResponse = (String) input.readObject(); // Receive server's response
        boolean clientAuthenticated = CryptoUtils.hash(clientChallenge + "serverSecret").equals(clientResponse);
        output.writeObject(clientAuthenticated); // Send authentication result to server
        output.flush();
        if (!clientAuthenticated) {
            System.out.println("Client authentication failed.");
            socket.close();
            return;
        }
        System.out.println("Client authenticated.");

        System.out.println("Shared secret key established.");

        // Step 9: Create an object of SecureData to send to the server
        SecureData data = new SecureData("Alice", "Confidential Message", 123.45);
        System.out.println("Original Data: " + data);

        // Step 10: Encrypt the SecureData object using SealedObject
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        SealedObject sealedObject = new SealedObject(data, cipher);

        // Step 11: Send the encrypted object to the server
        output.writeObject(sealedObject);
        output.flush();

        // Step 12: Close the connection
        socket.close();
    }
}