
import security.HashGen;
import security.RSAGen;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.Properties;
import security.OneTimeKeyGen;
import security.SSLClientSocket;

public class SSLClient {

    SSLClientSocket gClientSocket;
    BigInteger gBigInt_KU_Key; //publicKey
    BigInteger gBigInt_KU_n;
    BigInteger gBigInt_KR_Key; //PrivateKey
    BigInteger gBigInt_KR_n;

    public SSLClient(String pHostname, int pPort, String pUsername)
            throws Exception {
        Properties lClientProp = new Properties();
        FileInputStream lClientPropFileInpStream = new FileInputStream(pUsername + ".txt");
        lClientProp.load(lClientPropFileInpStream);
        lClientPropFileInpStream.close();
        String str = lClientProp.getProperty("company");
        StringBuilder lTempStr = new StringBuilder(lClientProp.getProperty("server.public_key"));
        int lLeftBraceIndex = lTempStr.indexOf("{");
        gBigInt_KU_Key = new BigInteger(lTempStr.substring(lLeftBraceIndex + 1, lTempStr.indexOf(",")));
        gBigInt_KU_n = new BigInteger(lTempStr.substring(lTempStr.indexOf(",") + 1, lTempStr.indexOf("}")));
        lTempStr = new StringBuilder(lClientProp.getProperty("private_key"));
        gBigInt_KR_Key = new BigInteger(lTempStr.substring(lLeftBraceIndex + 1, lTempStr.indexOf(",")));
        gBigInt_KR_n = new BigInteger(lTempStr.substring(lTempStr.indexOf(",") + 1, lTempStr.indexOf("}")));
        byte lPattern = (byte) Integer.parseInt(lClientProp.getProperty("pattern"));
        int lDataBytes = Integer.parseInt(lClientProp.getProperty("ndatabytes"));
        int lCheckBytes = Integer.parseInt(lClientProp.getProperty("ncheckbytes"));
        int lK = Integer.parseInt(lClientProp.getProperty("k"));

        HashGen lHash = new HashGen(lDataBytes, lCheckBytes, lPattern, lK);

        byte[] lArBy_en_company = RSAGen.cipher(str.getBytes(), gBigInt_KR_Key, gBigInt_KR_n);
        byte[] lArBy_key = OneTimeKeyGen.genNewKey(lDataBytes + lCheckBytes + 1);

        byte[] lArBy_en_key = RSAGen.cipher(lArBy_key, gBigInt_KU_Key, gBigInt_KU_n);

        byte[] lArBy_en_username = RSAGen.cipher(pUsername.getBytes(), gBigInt_KU_Key, gBigInt_KU_n);
        gClientSocket = new SSLClientSocket(pHostname, pPort, lArBy_en_username, lArBy_en_company, lArBy_en_key, lArBy_key, lHash);
    }

    public void execute()
            throws Exception {
        int i = 0;
        int j = 0;
        int k;

        while ((k = System.in.read()) != -1) {
            try {
                gClientSocket.getOutputStream().write(k);
            } catch (Exception ex) {
                System.out.println("Exception --->" + ex.getMessage());
            }
            if (((char) k == '\n') || ((char) k == '\r')) {
                gClientSocket.getOutputStream().flush();
            }
            i++;
        }
        gClientSocket.getOutputStream().flush();
        System.out.println("Response from Server ...\n\n");
        while ((k = gClientSocket.getInputStream().read()) != -1) {
            System.out.write(k);
            j++;
            if (j == i) {
                break;
            }
        }
        System.out.println();
        System.out.println("Streamed : " + j + " bytes");
        gClientSocket.close();
    }

    public static void main(String[] args)
            throws Exception {
        if (args.length != 3) {
            System.out.println("java Client <host> <port> <name>");
            System.exit(1);
        }
        System.out.println("Client Starting...");
        String lHostname = args[0];
        int lPort = Integer.parseInt(args[1]);
        String lUsername = args[2];
        new SSLClient(lHostname, lPort, lUsername).execute();
        System.out.println("Client Closing...");
    }
}
