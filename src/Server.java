import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.security.*;

/**
 * Server class that handles the Diffie-Hellman key exchange, receives encrypted data, and decrypts it.
 */
class Server {
    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(5050);
        System.out.println("Server started. Waiting for client...");

        // Accept client connection
        Socket clientSocket = serverSocket.accept();
        System.out.println("Client connected.");

        // Setup input and output streams
        ObjectInputStream input = new ObjectInputStream(clientSocket.getInputStream());
        ObjectOutputStream output = new ObjectOutputStream(clientSocket.getOutputStream());

        // Generate Server's DH key pair
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Send Server's public key to Client
        output.writeObject(keyPair.getPublic());
        output.flush();

        // Receive Client's public key
        PublicKey clientPublicKey = (PublicKey) input.readObject();

        // Generate shared secret key
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(clientPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

        System.out.println("Shared secret key established.");

        // Receive encrypted data
        byte[] encryptedData = (byte[]) input.readObject();
        byte[] decryptedData = CryptoUtils.decrypt(encryptedData, secretKey);

        // Deserialize object
        ByteArrayInputStream bis = new ByteArrayInputStream(decryptedData);
        ObjectInputStream ois = new ObjectInputStream(bis);
        SecureData receivedData = (SecureData) ois.readObject();

        System.out.println("Received decrypted data: " + receivedData);

        clientSocket.close();
        serverSocket.close();
    }
}

