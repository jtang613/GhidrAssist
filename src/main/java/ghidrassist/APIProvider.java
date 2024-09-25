package ghidrassist;

public class APIProvider {
    private String name;
    private String model;
    private String maxTokens;
    private String url;
    private String key;

    public APIProvider(String name, String model, String maxTokens, String url, String key) {
        this.name = name;
        this.model = model;
        this.maxTokens = maxTokens;
        this.url = url;
        this.key = key;
    }

    // Getters
    public String getName() { return name; }
    public String getModel() { return model; }
    public String getMaxTokens() { return maxTokens; }
    public String getUrl() { return url; }
    public String getKey() { return key; }

    // Setters
    public void setName(String name) { this.name = name; }
    public void setModel(String model) { this.model = model; }
    public void setMaxTokens(String maxTokens) { this.maxTokens = maxTokens; }
    public void setUrl(String url) { this.url = url; }
    public void setKey(String key) { this.key = key; }
}
