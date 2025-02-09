package ghidrassist;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.launchableinc.openai.client.OpenAiApi;
import com.launchableinc.openai.service.OpenAiService;
import okhttp3.*;
import retrofit2.Retrofit;
import retrofit2.adapter.rxjava2.RxJava2CallAdapterFactory;
import retrofit2.converter.jackson.JacksonConverterFactory;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.io.IOException;
import java.time.Duration;
import javax.net.ssl.*;

public class CustomOpenAiService {

    private final OpenAiService openAiService;

    public CustomOpenAiService(String apiKey, String apiHost, boolean disableTlsVerification) {
        this(apiKey, apiHost, disableTlsVerification, Duration.ofSeconds(240)); // Default timeout of 30 seconds
    }

    public CustomOpenAiService(String apiKey, String apiHost, boolean disableTlsVerification, Duration timeout) {
        OkHttpClient client = buildClient(apiKey, disableTlsVerification, timeout);
        Retrofit retrofit = buildRetrofit(client, apiHost);

        OpenAiApi api = retrofit.create(OpenAiApi.class);
        this.openAiService = new OpenAiService(api);
    }

    private OkHttpClient buildClient(String apiKey, boolean disableTlsVerification, Duration timeout) {
        try {
            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .addInterceptor(new AuthenticationInterceptor(apiKey))
                .connectTimeout(timeout)
                .readTimeout(timeout)
                .writeTimeout(timeout)
                .retryOnConnectionFailure(true)
                .addInterceptor(new RetryInterceptor(3)); // Add retry interceptor

            if (!disableTlsVerification) {
                return builder.build();
            }

            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}

                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[]{};
                    }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
            builder.hostnameVerifier((hostname, session) -> true);

            return builder.build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create a custom OkHttpClient", e);
        }
    }
    
    private Retrofit buildRetrofit(OkHttpClient client, String apiHost) {
        ObjectMapper objectMapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .configure(DeserializationFeature.FAIL_ON_INVALID_SUBTYPE, false)
                .configure(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, false)
                .configure(DeserializationFeature.FAIL_ON_UNRESOLVED_OBJECT_IDS, false)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);  

        return new Retrofit.Builder()
                .baseUrl(apiHost)
                .client(client)
                .addCallAdapterFactory(RxJava2CallAdapterFactory.create())
                .addConverterFactory(JacksonConverterFactory.create(objectMapper))
                .build();
    }

    public OpenAiService getOpenAiService() {
        return this.openAiService;
    }

    private static class AuthenticationInterceptor implements Interceptor {
        private final String apiKey;

        AuthenticationInterceptor(String apiKey) {
            this.apiKey = apiKey;
        }

        @Override
        public Response intercept(Chain chain) throws IOException {
            Request original = chain.request();
            Request request = original.newBuilder()
                    .header("Authorization", "Bearer " + apiKey)
                    .build();
            return chain.proceed(request);
        }
    }

    private static class RetryInterceptor implements Interceptor {
        private final int maxRetries;

        RetryInterceptor(int maxRetries) {
            this.maxRetries = maxRetries;
        }

        @Override
        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();
            Response response = null;
            IOException exception = null;

            int tryCount = 0;
            while (tryCount < maxRetries) {
                try {
                    response = chain.proceed(request);
                    if (response.isSuccessful()) {
                        return response;
                    } else {
                        response.close();
                    }
                } catch (IOException e) {
                    exception = e;
                }

                tryCount++;
                try {
                    Thread.sleep(1000 * tryCount); // Exponential backoff
                } catch (InterruptedException ignored) {}
            }

            if (exception != null) {
                throw exception;
            }
            return response;
        }
    }
}