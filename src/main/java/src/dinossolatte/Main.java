package src.dinossolatte;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Map.Entry;

import javax.xml.bind.DatatypeConverter;

import org.apache.log4j.Logger;

import src.dinossolatte.shared.CryptoFileHandler;
import src.dinossolatte.shared.Utils;

import org.apache.log4j.LogManager;

public class Main {
    private static Logger logger = LogManager.getRootLogger();
    private static SecureRandom rng = new SecureRandom();

    private static String[][] voteArray = { { "AMC", "26" }, { "JML", "16846" }, { "RMF", "100000" }, { "LCD", "1" } };

    public static void main(String[] args) {   
        // -- Obtención de datos del cliente --
        RSAPrivateKey privateKey = CryptoFileHandler.getPrivateKeyFromFile("src/main/resources/client/private.pkcs");
        X509Certificate certificate = CryptoFileHandler.getCertificateFromFile("src/main/resources/client/certificate.crt");
        RSAPublicKey publicKeyClient = (RSAPublicKey) certificate.getPublicKey();

        logger.debug(DatatypeConverter.printHexBinary(certificate.getSignature()).equals("385143b679694a7157af4ec3873a23ae7de90c6e6ee3587c010d3bf005c99cfb5c74bfaa63735d9f76aecca2616b021136c3b62c35f9c39c3534619a4569a6692040b9910e3ad3d2da2f5f8d2f6fd76d08b466386e9b8afdc3fa24dc748b94845867ee56dcebe5fb7bc45cb0753f4cd8ea0a29969501da12ce8deb318d61978da23641c2d99416b7e705ca2903de0bf030430edabbbed8701672b319c8e02d015d70564095d46a6c409dfd1b284c09db8374b357cd53a68e59b1d6c68d3b3986789f15e18c91ecb7b0fc9d966142ac256fe095cd9982b050ffcababd4fcee28c6b89e9f39af1b13a51d2e584359db29e50b97ea79681da2b4a359d9f635cdbf6".toUpperCase()));

        // Prueba de posesión del certificado
        try {
            MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = msgDigest.digest("Texto de prueba".getBytes());
            BigInteger test = new BigInteger(hash);
            BigInteger signatureTest = test.modPow(privateKey.getPrivateExponent(), privateKey.getModulus());
            BigInteger resultSignatureTest = signatureTest.modPow(publicKeyClient.getPublicExponent(), publicKeyClient.getModulus());
            if(hash == resultSignatureTest.toByteArray()) {
                System.out.println("Mismo hash");
            }            
        } catch(NoSuchAlgorithmException nsee) {

        }

        if(privateKey != null && certificate != null && DatatypeConverter.printHexBinary(certificate.getSignature()).equals("385143b679694a7157af4ec3873a23ae7de90c6e6ee3587c010d3bf005c99cfb5c74bfaa63735d9f76aecca2616b021136c3b62c35f9c39c3534619a4569a6692040b9910e3ad3d2da2f5f8d2f6fd76d08b466386e9b8afdc3fa24dc748b94845867ee56dcebe5fb7bc45cb0753f4cd8ea0a29969501da12ce8deb318d61978da23641c2d99416b7e705ca2903de0bf030430edabbbed8701672b319c8e02d015d70564095d46a6c409dfd1b284c09db8374b357cd53a68e59b1d6c68d3b3986789f15e18c91ecb7b0fc9d966142ac256fe095cd9982b050ffcababd4fcee28c6b89e9f39af1b13a51d2e584359db29e50b97ea79681da2b4a359d9f635cdbf6".toUpperCase())) {
            RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
            
            X509Certificate serverCertificate = CryptoFileHandler.getCertificateFromFile("src/main/resources/mainServer/certificate.crt");
            
            // == Por cada voto a cifrar ==
            Map<String[], BigInteger> finalVotes = new HashMap<String[], BigInteger>();

            RSAPublicKey serverPublicKey = (RSAPublicKey) serverCertificate.getPublicKey();
            RSAPrivateKey serverPrivateKey = CryptoFileHandler.getPrivateKeyFromFile("src/main/resources/mainServer/private.pkcs");

            for(String[] vote: voteArray) {
                // -- Proceso de ocultación del mensaje --
                BigInteger modulus = serverPublicKey.getModulus();
                BigInteger testMessage = new BigInteger(vote[0].getBytes());
                BigInteger blindingFactor = BigInteger.ONE;
                boolean isRelativePrime = false;
                while(isRelativePrime) {
                    blindingFactor = BigInteger.valueOf(Long.valueOf(vote[1]));
                    if(Utils.relativelyPrime(blindingFactor, modulus)) {
                        // Tenemos un valor correcto del factor de ocultación
                        isRelativePrime = true;
                    }
                }

                // msg = original^publicS * blindFactor mod modulus
                BigInteger blindMessage = blindingFactor.modPow(serverPublicKey.getPublicExponent(), modulus).multiply(testMessage).mod(modulus);

                logger.debug(blindMessage.toString());

                // -- Firma ciega del mensaje --

                // signature = msg^privateKeyS mod modulus
                BigInteger signature = blindMessage.modPow(serverPrivateKey.getPrivateExponent(), modulus); 
                // Comprobamos que la firma se haya hecho de forma correcta
                // checkSignature = signature^publicS mod modulus
                BigInteger checkSignature = signature.modPow(serverPublicKey.getPublicExponent(), modulus);
                logger.debug(signature.toString());
                logger.debug(checkSignature.toString());
                // checkSignature =? msg
                if(blindMessage.equals(checkSignature)) {
                    logger.debug("Signature is correct");
                } else {
                    logger.fatal("Signature is incorrect");
                }

                // -- Se envía el resultado al cliente --

                // originalSignature = original^privateS mod modulus
                BigInteger messageSignature = testMessage.modPow(serverPrivateKey.getPrivateExponent(), modulus);
                logger.debug(messageSignature.toString());

                // Se comprueba la firma ciega
                // msgCheck = signature * blindFactor^(-1) mod modulus
                BigInteger checkBlindSignature = signature.multiply(blindingFactor.modInverse(modulus)).mod(modulus);
                logger.debug(checkBlindSignature.toString());
                // originalSignature =? msgCheck
                if(checkBlindSignature.equals(messageSignature)) {
                    finalVotes.put(vote, checkBlindSignature);
                    logger.debug("Signature from server is correct");
                } else {
                    logger.fatal("Signature from server is incorrect");
                }
            }

            System.out.println("Votos finales: ");
            for(Entry<String[], BigInteger> entry : finalVotes.entrySet()) {
                System.out.println("Voto: "+entry.getKey()[0]+" | Blind factor: "+entry.getKey()[1]+" | Firma: "+DatatypeConverter.printHexBinary(entry.getValue().toByteArray()));
                BigInteger signature = new BigInteger(entry.getKey()[0].getBytes()).modPow(serverPrivateKey.getPrivateExponent(), serverPrivateKey.getModulus());
                if(entry.getValue().equals(signature)) {
                    // Misma firma, proceso de recuento es correcto.
                    System.out.println("La firma es correcta");
                } else {
                    System.out.println("La firma es incorrecta");
                }
            }

        } else {
            logger.fatal("Can't continue program without private and certificate!");
        }
    }
}