package src.dinossolatte.impl;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import org.apache.log4j.Logger;

import src.dinossolatte.shared.ExitConditionException;
import src.dinossolatte.shared.NetworkClient;
import src.dinossolatte.shared.NetworkClientRunnable;

import org.apache.log4j.LogManager;

public class IClient extends NetworkClient {
    private final InetAddress address;
    private final int port;
    private Logger logger = LogManager.getRootLogger();

    public IClient(NetworkClientRunnable runnable, InetAddress address, int port) {
        super(runnable);
        this.address = address;
        this.port = port;
        init();
    }

    public void init() {
        try {
            Socket clientSocket = new Socket(address, port);
            
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
                    exitCondition = false;
                } catch(Exception e) {
                    logger.warn("Exception thrown in server socket: ");
                    e.printStackTrace();
                }
                
            }
            clientSocket.close();
            
        } catch(Exception e) {
            logger.fatal("Exception: "+e.getMessage());
        }
        
    }
}