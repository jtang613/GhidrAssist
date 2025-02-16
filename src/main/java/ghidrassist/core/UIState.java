package ghidrassist.core;

public class UIState {
    private volatile boolean isQueryRunning;
    private int activeRunners;
    
    public UIState() {
        this.isQueryRunning = false;
        this.activeRunners = 0;
    }
    
    public synchronized boolean isQueryRunning() {
        return isQueryRunning;
    }
    
    public synchronized void setQueryRunning(boolean running) {
        this.isQueryRunning = running;
    }
    
    public synchronized void incrementRunners() {
        activeRunners++;
    }
    
    public synchronized void decrementRunners() {
        activeRunners--;
        if (activeRunners <= 0) {
            activeRunners = 0;
            isQueryRunning = false;
        }
    }
    
    public synchronized int getActiveRunners() {
        return activeRunners;
    }
}
