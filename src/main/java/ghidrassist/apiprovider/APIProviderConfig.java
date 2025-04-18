package ghidrassist.apiprovider;

import ghidrassist.GhidrAssistPlugin;

public class APIProviderConfig {
    private String name;
    private String model;
    private Integer maxTokens;
    private String url;
    private String key;
    private boolean disableTlsVerification;
    private APIProvider.ProviderType type;
    private Integer timeout;

    public APIProviderConfig(
            String name,
            APIProvider.ProviderType type,
            String model,
            Integer maxTokens,
            String url,
            String key,
            boolean disableTlsVerification) {
        this(name, type, model, maxTokens, url, key, disableTlsVerification, 120); // Default timeout of 120 seconds
    }

    public APIProviderConfig(
            String name,
            APIProvider.ProviderType type,
            String model,
            Integer maxTokens,
            String url,
            String key,
            boolean disableTlsVerification,
            Integer timeout) {
        this.name = name;
        this.type = type;
        this.model = model;
        this.maxTokens = maxTokens;
        this.url = url;
        this.key = key;
        this.disableTlsVerification = disableTlsVerification;
        this.timeout = timeout;
    }

    // Getters
    public String getName() { return name; }
    public APIProvider.ProviderType getType() { return type; }
    public String getModel() { return model; }
    public Integer getMaxTokens() { return maxTokens; }
    public String getUrl() { return url; }
    public String getKey() { return key; }
    public boolean isDisableTlsVerification() { return disableTlsVerification; }
    public Integer getTimeout() { return timeout; }

    // Setters
    public void setName(String name) { this.name = name; }
    public void setType(APIProvider.ProviderType type) { this.type = type; }
    public void setModel(String model) { this.model = model; }
    public void setMaxTokens(Integer maxTokens) { this.maxTokens = maxTokens; }
    public void setUrl(String url) { this.url = url; }
    public void setKey(String key) { this.key = key; }
    public void setDisableTlsVerification(boolean disableTlsVerification) { this.disableTlsVerification = disableTlsVerification; }
    public void setTimeout(Integer timeout) { this.timeout = timeout; }

    public APIProvider createProvider() {
    	this.timeout = GhidrAssistPlugin.getGlobalApiTimeout();
        switch (type) {
            case OPENAI:
                return new OpenAIProvider(name, model, maxTokens, url, key, disableTlsVerification, this.timeout);
            case ANTHROPIC:
                return new AnthropicProvider(name, model, maxTokens, url, key, disableTlsVerification, this.timeout);
            case OLLAMA:
                return new OllamaProvider(name, model, maxTokens, url, key, disableTlsVerification, this.timeout);
            case OPENWEBUI:
            	return new OpenWebUiProvider(name, model, maxTokens, url, key, disableTlsVerification, this.timeout);
            case LMSTUDIO:
                return new LMStudioProvider(name, model, maxTokens, url, key, disableTlsVerification, this.timeout);
            default:
                throw new IllegalArgumentException("Unsupported provider type: " + type);
        }
    }
}