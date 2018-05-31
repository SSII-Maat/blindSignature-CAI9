package src.dinossolatte.shared;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

public class CryptoFileHandler {
    private static Logger logger = LogManager.getRootLogger();

    public static RSAPrivateKey getPrivateKeyFromFile(String filename) {
        File privateKeyFile = new File(filename);
        RSAPrivateKey privateKey = null;
        
        try(
            FileInputStream fis = new FileInputStream(privateKeyFile);
            DataInputStream dis = new DataInputStream(fis);
        ) {
            byte[] keyArray = new byte[(int) privateKeyFile.length()];
            dis.readFully(keyArray);
            dis.close();

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        } catch(Exception e) {
            logger.error("Failed when attempting to get private key");
            logger.error("Error message: "+e.getMessage());
        }

        return privateKey;
    }

    public static X509Certificate getCertificateFromFile(String filename) {
        File certificateFile = new File(filename);
        X509Certificate certificate = null;

        try(
            FileInputStream fis = new FileInputStream(certificateFile);
            DataInputStream dis = new DataInputStream(fis);
        ) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) certFactory.generateCertificate(dis);
        } catch(Exception e) {
            logger.error("Failed when attempting to get certificate");
            logger.error("Error message: "+e.getMessage());
        }

        return certificate;
    }
}