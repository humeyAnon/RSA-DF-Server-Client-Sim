
// Client class - Initializes a socket and awaits for the client to request a connection
//                does Diffiehelman key exchange with RSA signature and HMAC - After all connected
//                Decrypts the message sent via Client and responds with its own encrypted message

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Client {

    private static Encryptions secret = new Encryptions();
    private static Socket socket = null;
    private static ObjectInputStream ois = null;
    private static ObjectOutputStream oos = null;
    private static BigInteger DHprivateKey, DHpublicKey, DHSessionKey, DHServerPublicKey;
    private static BigInteger publicKey;
    private static String clientID = "WEFWER453453FERGERGHERYERGERCVEGRRFRG", serverID, sessionID;

    public static void main(String [] args) throws IOException, ClassNotFoundException, InterruptedException, NoSuchAlgorithmException,
                                                   NoSuchPaddingException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidKeySpecException {

        InetAddress host = InetAddress.getLocalHost();

        socket = new Socket(host.getHostName(), 1234);
        oos = new ObjectOutputStream(socket.getOutputStream());
        System.out.println("Setup Phase\n-------------------------------\nClient to Server: Hello");

        oos.writeObject("Setup_Request: Hello");
        ois = new ObjectInputStream(socket.getInputStream());

        // Getting servers RSA public key
        System.out.println("Receiving RSA PK from Server");
        publicKey = new BigInteger(String.valueOf(ois.readObject()));

        // Sending clientID to server
        System.out.println("\nHandshake Phase\n-------------------------------\nClient to Server: IDc = " + clientID);
        oos.writeObject(clientID);

        // Storing the serverID
        serverID = (String) ois.readObject();
        System.out.println("Recieved Server ID: " + serverID);

        // Making DH private key
        DHprivateKey = secret.DHPrivateKey();

        // Making DH public key & sending to the server
        DHpublicKey = secret.DHPublicKey(DHprivateKey);

        oos.writeObject(DHpublicKey.toString());

        String serverKeys = (String) ois.readObject();
        String[] str = serverKeys.split(",");

        // Extract Servers DHpublicKey, signature, e
        // work out H(m) = s^e mod n
        String DHserverKey = str[0];
        DHServerPublicKey = new BigInteger(DHserverKey);
        BigInteger RsaS = new BigInteger(str[1]);
        BigInteger RsaN = new BigInteger(str[2]);

        // Close connection if the signature does not match up
        if(!secret.RSAsignatureVerify(DHserverKey, RsaS, RsaN, publicKey)) {
            System.out.println("RSA Signature did not match - Closing connection");
            closeConnection(ois, oos);
        }

        System.out.println("RSA Signature matched - Server is certified");

        // Create the Diffie session key - Kab = serversDiffiePublic ^ clientDiffiePrivate
        DHSessionKey = secret.DHSharedKey(DHServerPublicKey, DHprivateKey);

        //Create HMAC from session key + plain text message - Send both to server to check session keys
        String HMACMessage = secret.HMAC(DHSessionKey.toString(), "Hello please give me a good mark");
        oos.writeObject(HMACMessage + ",Hello please give me a good mark");

        // Confirming the session keys with HMAC
        String HMACServer = (String) ois.readObject();
        String[] str2 = HMACServer.split(",");

        String HMACmessageServer = secret.HMAC(DHSessionKey.toString(), str2[1]);

        if(!HMACmessageServer.equals(str2[0])) {
            System.out.println("Session key is invalid: Closing connection");
            oos.writeObject("Invalid");
            closeConnection(ois,oos);
        }

        // Session keys are confirmed - Sending an encrypted message to server
        System.out.println("Session keys confirmed\n\nData Exchange\n-------------------------------\nEncrypting & Sending message: There are 30 cows in a field and 28 chickens How many didnt?????");
        oos.writeObject(secret.encryptMessage(DHSessionKey.toString(), "There are 30 cows in a field and 28 chickens How many didnt?????"));

        // Wait for server to process the message
        Thread.sleep(1000);

        // Recieved message from server - checking if HMAC is verified
        String[] serverReply = (String[]) ois.readObject();
        System.out.println("Encrypted message received: " + serverReply[0] + serverReply[1] + serverReply[2]);

        if(!secret.HMAC(DHSessionKey.toString(), serverReply[0].concat(serverReply[1])).equals(serverReply[2])) {
            System.out.println("Failed HMAC check! - Closing connection");
            closeConnection(ois,oos);
        }

        // HMAC is correct - decrypt the message from cipher, IV and session key
        System.out.println("Message decrypted: " + secret.decryptMessage(DHSessionKey.toString(),serverReply[1],serverReply[0]) + "\nClosing connection..");

    }

    public static void closeConnection(ObjectInputStream ois, ObjectOutputStream oos) throws IOException {
        ois.close();
        oos.close();
        socket.close();
    }

}


