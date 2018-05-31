package src.dinossolatte.impl;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import src.dinossolatte.shared.ExitConditionException;
import src.dinossolatte.shared.NetworkClient;
import src.dinossolatte.shared.NetworkClientRunnable;

public class IServer extends NetworkClient {
    private ServerSocket serverSocket;
    private final int port;
    private Logger logger = LogManager.getRootLogger();

    public IServer(NetworkClientRunnable runnable, int port) {
        super(runnable);
        this.port = port;
        init();
    }

    public void init() {
        try {
            this.serverSocket = new ServerSocket(this.port);

            while(true) {
                Socket clientSocket = this.serverSocket.accept();

                boolean exitCondition = true;
                BufferedReader br = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                while(exitCondition) {
                    try {
                        byte[] response = super.runnable.sendingRun(clientSocket);
                        if(response != null) {
                            clientSocket.getOutputStream().write(response);
                            clientSocket.getOutputStream().flush();
                        }

                        byte[] clientMessage = br.readLine().getBytes();
                        response = super.runnable.receivingRun(clientMessage, clientSocket);
                        if(response != null) { 
                            clientSocket.getOutputStream().write(response);
                            clientSocket.getOutputStream().flush();
                        }
                    } catch(ExitConditionException ece) {
                        exitCondition = false; // TODO Cambiar, si hay tiempo
                    } catch(Exception e) {
                        logger.warn("Exception thrown in server socket: ");
                        e.printStackTrace();
                    }
                    
                }
                clientSocket.close();
            }
        } catch(Exception e) {
            logger.fatal("Exception: "+e.getMessage());
        }
    }
    
}