package security;

import java.math.BigInteger;
import java.util.Random;

public class RSAGen {
    public static byte[] cipher(byte[] lTextBytes, BigInteger pKey, BigInteger pN) {
        // byte[] lTextBytes = pText.getBytes();
        byte[] lTempByte1 = new byte[lTextBytes.length + 1];
        lTempByte1[0] = 0;
        for (int i = 0; i < lTextBytes.length; i++) {
            lTempByte1[(i + 1)] = lTextBytes[i];
        }
        byte[] lTempByte2 = new BigInteger(lTempByte1).modPow(pKey, pN).toByteArray();
        if (lTempByte2[0] != 0) {
            return lTempByte2;
        }
        byte[] lTempByte3 = new byte[lTempByte2.length - 1];
        System.arraycopy(lTempByte2, 1, lTempByte3, 0, lTempByte2.length - 1);
        return lTempByte3;
    }

    public static void main(String[] args) {
        BigInteger lBigInt_KU_Key;
        BigInteger lBigInt_KU_n;
        BigInteger lBigInt_KR_Key;
        BigInteger lBigInt_KR_n;
        Integer lPrimeSize = Integer.parseInt(System.getProperty("pSize"));
        BigInteger lBigInt_p = new BigInteger(lPrimeSize, 5, new Random());
        BigInteger lBigInt_q = new BigInteger(lPrimeSize, 5, new Random());
        BigInteger lBigInt_pMq = lBigInt_p.multiply(lBigInt_q);
        BigInteger lBigInt_qn = lBigInt_p.subtract(BigInteger.ONE).multiply(lBigInt_q.subtract(BigInteger.ONE));
        Random lRand = new Random();
        int i = lBigInt_qn.toByteArray().length;
        BigInteger lBigInt_rPrime;
        do {
            byte[] arrayOfByte = new byte[i];
            lRand.nextBytes(arrayOfByte);
            lBigInt_rPrime = new BigInteger(arrayOfByte).abs();
            lBigInt_rPrime = lBigInt_rPrime.mod(lBigInt_qn);
        } while (lBigInt_qn.gcd(lBigInt_rPrime).compareTo(BigInteger.ONE) != 0);
        BigInteger lBigInt_d = lBigInt_rPrime.modInverse(lBigInt_qn);
        //Private Key
        lBigInt_KR_Key = lBigInt_d;
        lBigInt_KR_n = lBigInt_pMq;
        //Public Key
        lBigInt_KU_Key = lBigInt_rPrime;
        lBigInt_KU_n = lBigInt_pMq;
        //Public Key and Private keys
        System.out.println("RSA Generator");
        System.out.println("-------------");
        System.out.println(
                '{' + lBigInt_KU_Key.toString() + ',' + lBigInt_KU_n.toString() + '}');
        System.out.println(
                '{' + lBigInt_KR_Key.toString() + ',' + lBigInt_KR_n.toString() + '}');
        //cipher Operation--
        System.out.println("Original Message : " + args[1]);
        byte[] lSecretMsg = cipher(args[1].getBytes(), lBigInt_KU_Key, lBigInt_KU_n);
        byte[] lSecretMsg2 = cipher(args[1].getBytes(), lBigInt_KR_Key, lBigInt_KR_n);
        System.out.println("Secret : " + lSecretMsg.toString());
        String lMsg = new String(cipher(lSecretMsg, lBigInt_KR_Key, lBigInt_KR_n));
        String lMsg2 = new String(cipher(lSecretMsg2, lBigInt_KU_Key, lBigInt_KU_n));
        System.out.println("Message : " + lMsg);
        System.out.println("Message : " + lMsg2);
    }
}