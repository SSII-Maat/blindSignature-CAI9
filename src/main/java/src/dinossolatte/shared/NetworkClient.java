package src.dinossolatte.shared;

public abstract class NetworkClient {
    protected NetworkClientRunnable runnable;

    public NetworkClient(NetworkClientRunnable runnable) {
        // Inicialización de contenido
        init();
        this.runnable = runnable;
    }

    public abstract void init();
}