package ghidrassist.apiprovider;

public class APIProviderConfig {
    private String name;
    private String model;
    private Integer maxTokens;
    private String url;
    private String key;
    private boolean disableTlsVerification;
    private APIProvider.ProviderType type;

    public APIProviderConfig(String name, APIProvider.ProviderType type, String model, Integer maxTokens, 
                           String url, String key, boolean disableTlsVerification) {
        this.name = name;
        this.type = type;
        this.model = model;
        this.maxTokens = maxTokens;
        this.url = url;
        this.key = key;
        this.disableTlsVerification = disableTlsVerification;
    }

    // Getters
    public String getName() { return name; }
    public APIProvider.ProviderType getType() { return type; }
    public String getModel() { return model; }
    public Integer getMaxTokens() { return maxTokens; }
    public String getUrl() { return url; }
    public String getKey() { return key; }
    public boolean isDisableTlsVerification() { return disableTlsVerification; }

    // Setters
    public void setName(String name) { this.name = name; }
    public void setType(APIProvider.ProviderType type) { this.type = type; }
    public void setModel(String model) { this.model = model; }
    public void setMaxTokens(Integer maxTokens) { this.maxTokens = maxTokens; }
    public void setUrl(String url) { this.url = url; }
    public void setKey(String key) { this.key = key; }
    public void setDisableTlsVerification(boolean disableTlsVerification) { this.disableTlsVerification = disableTlsVerification; }

    public APIProvider createProvider() {
        switch (type) {
            case OPENAI:
                return new OpenAIProvider(name, model, maxTokens, url, key, disableTlsVerification);
            case ANTHROPIC:
                return new AnthropicProvider(name, model, maxTokens, url, key, disableTlsVerification);
            case OLLAMA:
                return new OllamaProvider(name, model, maxTokens, url, key, disableTlsVerification);
            case OPENWEBUI:
            	return new OpenWebUiProvider(name, model, maxTokens, url, key, disableTlsVerification);
            case LMSTUDIO:
                return new LMStudioProvider(name, model, maxTokens, url, key, disableTlsVerification);
            default:
                throw new IllegalArgumentException("Unsupported provider type: " + type);
        }
    }
}