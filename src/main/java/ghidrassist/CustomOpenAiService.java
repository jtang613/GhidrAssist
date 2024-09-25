package ghidrassist;

import com.launchableinc.openai.client.OpenAiApi;
import com.launchableinc.openai.service.OpenAiService;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;
import java.io.IOException;
import java.time.Duration;
import javax.net.ssl.*;

public class CustomOpenAiService {

    private final OpenAiService openAiService;

    /**
     * Constructor that accepts the API key and API host.
     *
     * @param apiKey  Your OpenAI API key.
     * @param apiHost The API host URL (e.g., "https://api.openai.com/").
     */
    public CustomOpenAiService(String apiKey, String apiHost) {
        this(apiKey, apiHost, Duration.ofSeconds(60));
    }

    /**
     * Constructor that accepts the API key, API host, and timeout duration.
     *
     * @param apiKey  Your OpenAI API key.
     * @param apiHost The API host URL.
     * @param timeout The timeout duration for API calls.
     */
    public CustomOpenAiService(String apiKey, String apiHost, Duration timeout) {
        OkHttpClient client = buildClient(apiKey, timeout);

        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl(apiHost)
                .client(client)
                .addConverterFactory(JacksonConverterFactory.create())
                .build();

        OpenAiApi api = retrofit.create(OpenAiApi.class);
        this.openAiService = new OpenAiService(api);
    }

    /**
     * Builds a custom OkHttpClient with the API key, timeout, and disabled SSL certificate validation.
     *
     * @param apiKey  Your OpenAI API key.
     * @param timeout The timeout duration for API calls.
     * @return Configured OkHttpClient instance.
     */
    private OkHttpClient buildClient(String apiKey, Duration timeout) {
        try {
            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                        // Do nothing: Trust all client certificates
                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                        // Do nothing: Trust all server certificates
                    }

                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[]{};
                    }
                }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            // Create an SSL socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient.Builder builder = new OkHttpClient.Builder();
            builder.callTimeout(timeout)
                    .sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0])
                    .hostnameVerifier((hostname, session) -> true) // Trust all hostnames
                    .addInterceptor(new AuthenticationInterceptor(apiKey));

            return builder.build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create a custom OkHttpClient with disabled SSL validation", e);
        }
    }

    /**
     * Returns the configured OpenAiService instance.
     *
     * @return OpenAiService instance.
     */
    public OpenAiService getOpenAiService() {
        return this.openAiService;
    }

    /**
     * Interceptor to add the Authorization header to requests.
     */
    private static class AuthenticationInterceptor implements Interceptor {
        private final String apiKey;

        AuthenticationInterceptor(String apiKey) {
            this.apiKey = apiKey;
        }

        @Override
        public Response intercept(Chain chain) throws IOException {
            Request original = chain.request();

            // Add the Authorization header with the API key
            Request request = original.newBuilder()
                    .header("Authorization", "Bearer " + apiKey)
                    .build();

            return chain.proceed(request);
        }
    }
}
