package src.dinossolatte.shared;

import java.net.Socket;

public abstract class NetworkClientRunnable {
    public abstract byte[] sendingRun(Socket clientSocket) throws Exception;
    public abstract byte[] receivingRun(byte[] response, Socket clientSocket) throws Exception;
}