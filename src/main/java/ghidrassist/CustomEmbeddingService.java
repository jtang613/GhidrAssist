package ghidrassist;

import java.io.IOException;
import java.security.cert.CertificateException;
import javax.net.ssl.*;
import okhttp3.*;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;

public class CustomEmbeddingService {

    private String apiKey;
    private String apiUrl;
    private String apiModel;
    private boolean disableTlsVerification;
    private static final Gson gson = new Gson();
    private OkHttpClient client;
    private EmbeddingProvider embeddingProvider;
    

    public CustomEmbeddingService() {
    }

    public void init() {
    	try {
	    	APIProvider currentProvider = GhidrAssistPlugin.getCurrentAPIProvider();
	        this.apiKey = currentProvider.getKey();
	        this.apiUrl = currentProvider.getUrl();
	        this.apiModel = currentProvider.getModel();
	        this.disableTlsVerification = currentProvider.isDisableTlsVerification();
    	}
    	catch (Exception e) {
    		Msg.showError(this, null, "Service Error", "You must configure at least one API Provider.");
    	}
    }

    public enum EmbeddingProvider {
        OPENAI, OLLAMA, LMS, NONE
    }

    public double[] getEmbedding(String text) throws IOException {
    	this.init();
    	embeddingProvider = EmbeddingProvider.valueOf(Preferences.getProperty("GhidrAssist.SelectedRAGProvider", "NONE"));
        switch (embeddingProvider) {
            case OLLAMA:
                return getOllamaEmbedding(text);
            case OPENAI:
                return getOpenAIEmbedding(text);
            case LMS:
                return getLMSEmbedding(text);
            case NONE:
            default:
                return new double[0]; // Return an empty result list
        }
    }

    private static OkHttpClient createHttpClient(boolean disableTlsVerification) {
        try {
            OkHttpClient.Builder builder = new OkHttpClient.Builder();

            if (!disableTlsVerification) {
                return builder.build();
            }

            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {}
                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {}
                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[]{}; }
                }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            builder.sslSocketFactory(sslSocketFactory, (X509TrustManager)trustAllCerts[0]);
            builder.hostnameVerifier((hostname, session) -> true);

            return builder.build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private double[] getOllamaEmbedding(String text) throws IOException {
        String url = apiUrl.replace("v1/", "ollama/api/") + "embeddings";

        JsonObject payload = new JsonObject();
        payload.addProperty("model", this.apiModel);
        payload.addProperty("keep_alive", 0);
        payload.addProperty("prompt", text);
        payload.add("options", new JsonObject());

        RequestBody body = RequestBody.create(MediaType.get("application/json; charset=utf-8"), gson.toJson(payload));
        Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + apiKey)
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .post(body)
                .build();

        client = createHttpClient(disableTlsVerification);
        Response response = client.newCall(request).execute();
        if (!response.isSuccessful()) {
            System.out.println("Failed to get embedding: " + response.code() + "\n" + response.message());
            throw new IOException("Failed to get embedding: " + response.code() + "\n" + response.message());
        }

        String responseString = response.body().string();
        JsonObject responseObject = (JsonObject) gson.fromJson(responseString, JsonElement.class);
        JsonArray embeddingsArray = responseObject.getAsJsonArray("embedding");
        if (embeddingsArray == null || embeddingsArray.size() == 0) {
            throw new IOException("No embeddings found in the response");
        }

        JsonArray embeddings = embeddingsArray;
        double[] embeddingArray = new double[embeddings.size()];
        for (int i = 0; i < embeddings.size(); i++) {
            embeddingArray[i] = embeddings.get(i).getAsDouble();
        }
        return embeddingArray;
    }

    private double[] getLMSEmbedding(String text) throws IOException {
        String url = apiUrl + "embeddings";

        JsonObject payload = new JsonObject();
        payload.addProperty("model", "text-embedding-nomic-embed-text-v1.5"); // Default LMS text embedding model
        payload.addProperty("encoding_format", "float");
        payload.addProperty("input", text);
        payload.add("options", new JsonObject());

        RequestBody body = RequestBody.create(MediaType.get("application/json; charset=utf-8"), gson.toJson(payload));
        Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + apiKey)
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .post(body)
                .build();

        client = createHttpClient(disableTlsVerification);
        Response response = client.newCall(request).execute();
        if (!response.isSuccessful()) {
            System.out.println("Failed to get embedding: " + response.code() + "\n" + response.message());
            throw new IOException("Failed to get embedding: " + response.code() + "\n" + response.message());
        }

        String responseString = response.body().string();
        JsonObject responseObject = (JsonObject) gson.fromJson(responseString, JsonElement.class);
        // Get the "data" array
        JsonArray dataArray = responseObject.getAsJsonArray("data");
        // Get the first object in the data array
        JsonObject embeddingObject = dataArray.get(0).getAsJsonObject();
        // Get the "embedding" array
        JsonArray embeddingsArray = embeddingObject.getAsJsonArray("embedding");
        if (embeddingsArray == null || embeddingsArray.size() == 0) {
            throw new IOException("No embeddings found in the response");
        }

        JsonArray embeddings = embeddingsArray;
        double[] embeddingArray = new double[embeddings.size()];
        for (int i = 0; i < embeddings.size(); i++) {
            embeddingArray[i] = embeddings.get(i).getAsDouble();
        }
        return embeddingArray;
    }

    private double[] getOpenAIEmbedding(String text) throws IOException {
        String url = apiUrl + "embeddings";

        JsonObject payload = new JsonObject();
        payload.addProperty("model", "text-embedding-ada-002");
        payload.addProperty("encoding_format", "float");
        payload.addProperty("input", text);

        RequestBody body = RequestBody.create(MediaType.get("application/json; charset=utf-8"), gson.toJson(payload));
        Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + apiKey)
                .addHeader("Content-Type", "application/json")
                .post(body)
                .build();

        client = createHttpClient(disableTlsVerification);
        Response response = client.newCall(request).execute();
        if (!response.isSuccessful()) {
            System.out.println("Failed to get embedding: " + response.code() + "\n" + response.message());
            throw new IOException("Failed to get embedding: " + response.code() + "\n" + response.message());
        }

        String responseString = response.body().string();
        JsonObject responseObject = gson.fromJson(responseString, JsonObject.class);
        JsonArray dataArray = responseObject.getAsJsonArray("data");
        JsonArray embeddingsArray = dataArray.get(0).getAsJsonObject().getAsJsonArray("embedding");
        if (embeddingsArray == null || embeddingsArray.size() == 0) {
            throw new IOException("No embeddings found in the response");
        }

        JsonArray embeddings = embeddingsArray;
        double[] embeddingArray = new double[embeddings.size()];
        for (int i = 0; i < embeddings.size(); i++) {
            embeddingArray[i] = embeddings.get(i).getAsDouble();
        }
        return embeddingArray;
    }
}