package src.dinossolatte;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.log4j.Logger;

import src.dinossolatte.shared.CryptoFileHandler;

import org.apache.log4j.LogManager;

public class Main {
    private static Logger logger = LogManager.getRootLogger();
    private static SecureRandom rng = new SecureRandom();

    public static void main(String[] args) {   
        // -- Obtención de datos del cliente --
        RSAPrivateKey privateKey = CryptoFileHandler.getPrivateKeyFromFile("src/main/resources/client/private.pkcs");
        X509Certificate certificate = CryptoFileHandler.getCertificateFromFile("src/main/resources/client/certificate.crt");

        if(privateKey != null && certificate != null) {
            RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
            
            // TODO Establecer mensaje y transpaso de información
            X509Certificate serverCertificate = CryptoFileHandler.getCertificateFromFile("src/main/resources/mainServer/certificate.crt");
            
            // -- Proceso de ocultación del mensaje --

            RSAPublicKey serverPublicKey = (RSAPublicKey) serverCertificate.getPublicKey();
            BigInteger modulus = serverPublicKey.getModulus();
            BigInteger testMessage = new BigInteger("Test message".getBytes());
            BigInteger blindingFactor = BigInteger.valueOf(rng.nextInt());

            BigInteger blindMessage = blindingFactor.modPow(serverPublicKey.getPublicExponent(), modulus).multiply(testMessage).mod(modulus);

            logger.debug(blindMessage.toString());

            // TODO Enviar mensaje

            // -- Firma ciega del mensaje --

            RSAPrivateKey serverPrivateKey = CryptoFileHandler.getPrivateKeyFromFile("src/main/resources/mainServer/private.pkcs");
            BigInteger signature = blindMessage.modPow(serverPrivateKey.getPrivateExponent(), modulus);
            // Comprobamos que la firma se haya hecho de forma correcta
            BigInteger checkSignature = signature.modPow(serverPublicKey.getPublicExponent(), modulus);
            logger.debug(signature.toString());
            logger.debug(checkSignature.toString());
            if(blindMessage.equals(checkSignature)) {
                logger.debug("Signature is correct");
            } else {
                logger.fatal("Signature is incorrect");
            }

            BigInteger messageSignature = testMessage.modPow(serverPrivateKey.getPrivateExponent(), modulus);
            logger.debug(messageSignature.toString());

            // -- Se envía el resultado al cliente --

            // Se comprueba la firma ciega
            BigInteger checkBlindSignature = signature.multiply(blindingFactor.modInverse(modulus)).mod(modulus);
            logger.debug(checkBlindSignature.toString());
            if(checkBlindSignature.equals(messageSignature)) {
                logger.debug("Signature from server is correct");
            } else {
                logger.fatal("Signature from server is incorrect");
            }
        } else {
            logger.fatal("Can't continue program without private and certificate!");
        }
    }
}