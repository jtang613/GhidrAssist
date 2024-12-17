package ghidrassist;

public class APIProvider {
    private String name;
    private String model;
    private String maxTokens;
    private String url;
    private String key;
    private boolean disableTlsVerification;

    public APIProvider(String name, String model, String maxTokens, String url, String key, boolean disableTlsVerification) {
        this.name = name;
        this.model = model;
        this.maxTokens = maxTokens;
        this.url = url;
        this.key = key;
        this.disableTlsVerification = disableTlsVerification;
    }

    // Getters
    public String getName() { return name; }
    public String getModel() { return model; }
    public String getMaxTokens() { return maxTokens; }
    public String getUrl() { return url; }
    public String getKey() { return key; }
    public boolean isDisableTlsVerification() { return disableTlsVerification; }

    // Setters
    public void setName(String name) { this.name = name; }
    public void setModel(String model) { this.model = model; }
    public void setMaxTokens(String maxTokens) { this.maxTokens = maxTokens; }
    public void setUrl(String url) { this.url = url; }
    public void setKey(String key) { this.key = key; }
    public void setDisableTlsVerification(boolean disableTlsVerification) { this.disableTlsVerification = disableTlsVerification; }
}
