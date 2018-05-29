
import java.io.FileInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;
import security.SSLClientSocket;
import security.SSLServerSocket;

public class SSLServer
        implements Runnable {

    BigInteger gBigInt_KU_Key; //publicKey
    BigInteger gBigInt_KU_n;
    BigInteger gBigInt_KR_Key; //PrivateKey
    BigInteger gBigInt_KR_n;
    // private RSA.PrivateKey serverPrivateKey;
    private Properties gProperties;
    private SSLServerSocket gServerSocket;
    private int gServerPort;

    public SSLServer()
            throws Exception {
        byte[] lEnPrivateKey = Files.readAllBytes(Paths.get("private_key.txt"));
        String lServerPrivateKey = new String(lEnPrivateKey, "UTF-8");
        StringBuilder lTempStr = new StringBuilder(lServerPrivateKey);
        int lLeftBraceIndex = lTempStr.indexOf("{");
        gBigInt_KR_Key = new BigInteger(lTempStr.substring(lLeftBraceIndex + 1, lTempStr.indexOf(",")));
        gBigInt_KR_n = new BigInteger(lTempStr.substring(lTempStr.indexOf(",") + 1, lTempStr.indexOf("}")));
        String str2 = "users.txt";
        FileInputStream lFileInputStream = new FileInputStream(str2);
        this.gProperties = new Properties();
        this.gProperties.load(lFileInputStream);
        lFileInputStream.close();
        String str3 = System.getProperty("server.port");
        if (str3 != null) {
            gServerPort = Integer.parseInt(str3);
        } else {
            gServerPort = 5000;
        }
        gServerSocket = new SSLServerSocket(gServerPort, gBigInt_KR_Key, gBigInt_KR_n, this.gProperties);
        System.out.println("Waiting for Incoming Connection...");
    }

    public class RequestHandler
            implements Runnable {

        private SSLClientSocket socket;

        public RequestHandler(SSLClientSocket paramSSLSocket) {
            socket = paramSSLSocket;
        }

        public void run() {
            try {
                System.out.println("Incoming Request...");
                int i;
                while ((i = socket.getInputStream().read()) != -1) {
                    if ((i >= 97) && (i <= 122)) {
                        i -= 32;
                    } else if ((i >= 65) && (i <= 90)) {
                        i += 32;
                    }
                    socket.getOutputStream().write(i);
                    if (socket.getInputStream().available() == 0) {
                        socket.getOutputStream().flush();
                    }
                }
                socket.getOutputStream().flush();
                socket.close();
                System.out.println("Request Processed...\n\n");
                System.out.println("Waiting for Next Connection...");
                return;
            } catch (Exception localException) {
                System.out.println("HANDLER: " + localException);
            }
        }
    }

    public void run() {
        try {
            for (;;) {
                new Thread(new SSLServer.RequestHandler((SSLClientSocket) this.gServerSocket.accept())).run();
            }
        } catch (Exception localException) {
            System.out.println("SERVER: " + localException);
        }
    }

    public static void main(String[] paramArrayOfString)
            throws Exception {
        System.out.println("Starting Server...");
        new SSLServer().run();
        System.out.println("Server Stopped...");
    }
}
