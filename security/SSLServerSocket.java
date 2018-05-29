package security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;

public class SSLServerSocket
        extends ServerSocket {

    BigInteger gBigInt_KR_Key; //PrivateKey
    BigInteger gBigInt_KR_n;
    protected Properties gProperties;

    public SSLServerSocket(int pPort, BigInteger pKR_Key, BigInteger pKR_n, Properties pProperties)
            throws IOException {
        super(pPort);
        gBigInt_KR_Key = pKR_Key;
        gBigInt_KR_n = pKR_n;
        gProperties = pProperties;
    }

    public Socket accept()
            throws IOException {
        Socket localSocket = super.accept();
        byte[] oneTimeKey = null;
        HashGen hash = null;
        try {
            Object[] params = handshake(localSocket);
            oneTimeKey = (byte[]) params[0];
            hash = (HashGen) params[1];
        } catch (Exception localException) {
            throw new IOException(localException.toString());
        }
        return new SSLClientSocket(localSocket, oneTimeKey, hash);
    }

    protected Object[] handshake(Socket socket)
            throws Exception {
        System.out.println("Analysing Handshake...");
        ObjectInputStream iStream = new ObjectInputStream(socket.getInputStream());
        SSLPacketAssembly lReceivedPacket;
        if ((lReceivedPacket = (SSLPacketAssembly) iStream.readObject()) == null) {
            throw new IOException("bad handshake packet format");
        }
        byte[] lUsername = lReceivedPacket.gUsername;
        byte[] lCompany = lReceivedPacket.gCompany;
        byte[] lKey = lReceivedPacket.gKey;

        String lDecryptedUsername = new String(RSAGen.cipher(lUsername, gBigInt_KR_Key, gBigInt_KR_n));
        System.out.println("Username : " + lDecryptedUsername);
        String publicKey = gProperties.getProperty(lDecryptedUsername + ".public_key");
        BigInteger lBigInt_KU_Key; //publicKey
        BigInteger lBigInt_KU_n;
        if (publicKey == null) {
            throw new Exception("The Username : " + lDecryptedUsername + " not registered");
        }
        StringBuilder lTempStr = new StringBuilder(publicKey);
        int lLeftBraceIndex = lTempStr.indexOf("{");
        lBigInt_KU_Key = new BigInteger(lTempStr.substring(lLeftBraceIndex + 1, lTempStr.indexOf(",")));
        lBigInt_KU_n = new BigInteger(lTempStr.substring(lTempStr.indexOf(",") + 1, lTempStr.indexOf("}")));
        String comp = new String(RSAGen.cipher(lCompany, lBigInt_KU_Key, lBigInt_KU_n));
        System.out.println("Company  : " + comp);
        if (!comp.equals(gProperties.getProperty(lDecryptedUsername + ".company"))) {
            throw new Exception("The Company Name : " + comp + " is not registered for user " + lDecryptedUsername);
        }
        int lDataBytes = Integer.parseInt(this.gProperties.getProperty(lDecryptedUsername + ".ndatabytes"));
        int lCheckBytes = Integer.parseInt(this.gProperties.getProperty(lDecryptedUsername + ".ncheckbytes"));
        byte lPattern = (byte) Integer.parseInt(this.gProperties.getProperty(lDecryptedUsername + ".pattern"));
        int lK = Integer.parseInt(this.gProperties.getProperty(lDecryptedUsername + ".k"));
        Object[] params = new Object[2];
        params[0] = RSAGen.cipher(lKey, gBigInt_KR_Key, gBigInt_KR_n);
        params[1] = new HashGen(lDataBytes, lCheckBytes, lPattern, lK);
        System.out.println("Handshake Accepted...");
        return params;
    }
}
