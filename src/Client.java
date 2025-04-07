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
        Socket socket = new Socket("localhost", 5050);
        System.out.println("Client attempting to connect to localhost:5050...");
        System.out.println("Connected to server.");

        // Setup input and output streams
        ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

        // Receive Server's public key
        PublicKey serverPublicKey = (PublicKey) input.readObject();

        // Generate Client's DH key pair
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(((DHPublicKey) serverPublicKey).getParams());
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Send Client's public key to Server
        output.writeObject(keyPair.getPublic());
        output.flush();

        // Generate shared secret key
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

        // Authenticate the server
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

        // Authenticate the client
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

        // Create SecureData object
        SecureData data = new SecureData("Alice", "Confidential Message", 123.45);
        System.out.println("Original Data: " + data);

        // Encrypt SecureData object using SealedObject
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        SealedObject sealedObject = new SealedObject(data, cipher);

        // Send SealedObject
        output.writeObject(sealedObject);
        output.flush();

        socket.close();
    }
}