package src.dinossolatte.impl;

import java.math.BigInteger;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import src.dinossolatte.shared.CryptoFileHandler;
import src.dinossolatte.shared.ExitConditionException;
import src.dinossolatte.shared.NetworkClientRunnable;

public class ServerImpl extends NetworkClientRunnable{
    private int currentState;
    private X509Certificate serverCertificate;
    private RSAPublicKey serverPublicKey;
    private RSAPrivateKey serverPrivateKey;

    public ServerImpl() {
        this.currentState = 0;
        this.serverCertificate = CryptoFileHandler.getCertificateFromFile("src/main/resources/mainServer/certificate.crt");
        this.serverPublicKey = (RSAPublicKey) serverCertificate.getPublicKey();
        this.serverPrivateKey = CryptoFileHandler.getPrivateKeyFromFile("src/main/resources/mainServer/private.pkcs");
    }
    
    public byte[] receivingRun(byte[] response, Socket clientSocket) throws Exception {
        byte[] result = null;

        switch(this.currentState) {
            case 0:
                // En este caso, hemos inicializado la conversación. El primer mensaje vendrá del cliente y será el mensaje ciego
                // Debemos firmar con nuestra clave privada y enviarla la firma para comprobar
                BigInteger message = new BigInteger(response);
                BigInteger privateExponent = this.serverPrivateKey.getPrivateExponent();
                BigInteger modulus = this.serverPrivateKey.getModulus();
                BigInteger signature = message.modPow(privateExponent, modulus);
                // Lo enviamos al cliente
                result = signature.toByteArray();
                this.currentState++;
                break;
            case 1:
                // En este caso, deberíamos recibir confirmación de si el mensaje no haya sido modificado, comprobamos la respuesta:
                String responseMessage = new String(response);
                if(responseMessage.equals("OK")) {
                    // Todo ha ido bien, cerramos la conexión
                    throw new ExitConditionException(); // TODO Cambiar esto, no es bueno.
                } else {
                    
                }
                break;

        }

		return result;
	}

	
	public byte[] sendingRun(Socket clientSocket) throws Exception {
        byte[] result = null;

		return result;
	}
	
}