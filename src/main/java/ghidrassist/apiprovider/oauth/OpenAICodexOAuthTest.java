package ghidrassist.apiprovider.oauth;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

/**
 * Standalone test client for OpenAI Codex OAuth authentication.
 * 
 * This is a direct translation of the working Python client at:
 * /home/jtang613/ml/symgraph/openai_codex_oauth_client.py
 * 
 * Run this to test OAuth flow independently before integrating with GhidrAssist.
 * 
 * Usage: java OpenAICodexOAuthTest
 */
public class OpenAICodexOAuthTest {
    
    // OAuth Configuration - From Codex CLI (codex-cli-rs)
    private static final String CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
    private static final String AUTH_URL = "https://auth.openai.com/oauth/authorize";
    private static final String TOKEN_URL = "https://auth.openai.com/oauth/token";
    private static final String REDIRECT_URI = "http://localhost:1455/auth/callback";
    private static final String OAUTH_SCOPES = "openid profile email offline_access";
    
    private static final Gson gson = new Gson();
    
    public static void main(String[] args) throws Exception {
        System.out.println("OpenAI Codex OAuth Test Client");
        System.out.println("=".repeat(50));
        
        // If arguments provided, use them for token exchange
        if (args.length >= 2) {
            String code = args[0];
            String verifier = args[1];
            System.out.println("\nUsing provided code and verifier for token exchange...");
            System.out.println("Code: " + code.substring(0, Math.min(20, code.length())) + "...");
            System.out.println("Verifier: " + verifier.substring(0, 20) + "...");
            
            JsonObject tokens = exchangeCodeForTokens(code, verifier);
            if (tokens.has("error")) {
                System.out.println("ERROR: " + tokens.get("error").getAsString());
                if (tokens.has("error_description")) {
                    System.out.println("Description: " + tokens.get("error_description").getAsString());
                }
            } else {
                System.out.println("\nSUCCESS! Tokens received:");
                System.out.println("  Access token: " + tokens.get("access_token").getAsString().substring(0, 30) + "...");
                if (tokens.has("refresh_token")) {
                    System.out.println("  Refresh token: " + tokens.get("refresh_token").getAsString().substring(0, 30) + "...");
                }
            }
            return;
        }
        
        // Generate PKCE
        String verifier = generateCodeVerifier();
        String challenge = generateCodeChallenge(verifier);
        String state = generateState();
        
        System.out.println("\nGenerated PKCE:");
        System.out.println("  Verifier: " + verifier.substring(0, 20) + "...");
        System.out.println("  Challenge: " + challenge.substring(0, 20) + "...");
        System.out.println("  State: " + state.substring(0, 20) + "...");
        
        // Build authorization URL
        String authUrl = buildAuthorizeUrl(challenge, state);
        
        System.out.println("\nAuthorization URL:");
        System.out.println(authUrl);
        System.out.println();
        
        // Open browser
        System.out.println("Opening browser for authorization...");
        openBrowser(authUrl);
        
        System.out.println("\nAfter authorizing, the browser will redirect to a page that won't load.");
        System.out.println("This is expected! Look at the URL bar - it will look like:");
        System.out.println("  http://localhost:1455/auth/callback?code=XXXX&state=YYYY");
        System.out.println();
        System.out.println("You can paste either:");
        System.out.println("  - The full URL from the browser");
        System.out.println("  - Just the 'code' value (the part after 'code=' and before '&')");
        System.out.println();
        
        // Check if we have interactive input
        String userInput = null;
        if (System.console() != null) {
            userInput = System.console().readLine("Paste the code or full URL here: ");
        } else {
            // Try Scanner, but handle non-interactive mode
            // Note: Intentionally not closing Scanner(System.in) as it would close System.in
            @SuppressWarnings("resource")
            Scanner scanner = new Scanner(System.in);
            System.out.print("Paste the code or full URL here: ");
            if (scanner.hasNextLine()) {
                userInput = scanner.nextLine();
            }
        }
        
        if (userInput == null || userInput.trim().isEmpty()) {
            System.out.println("\nNo input provided. To complete authentication:");
            System.out.println("1. Open the URL above in your browser");
            System.out.println("2. Log in and authorize");
            System.out.println("3. Copy the 'code' from the redirect URL");
            System.out.println("4. Run this test again with the code as an argument:");
            System.out.println("   java ... OpenAICodexOAuthTest <code> <verifier>");
            System.out.println("\nVerifier to use: " + verifier);
            return;
        }
        userInput = userInput.trim();
        
        // Extract code from URL if needed
        String code = extractCode(userInput);
        System.out.println("Using code: " + code.substring(0, Math.min(20, code.length())) + "...");
        
        // Exchange code for tokens
        System.out.println("\nExchanging code for tokens...");
        JsonObject tokens = exchangeCodeForTokens(code, verifier);
        
        if (tokens.has("error")) {
            System.out.println("ERROR: " + tokens.get("error").getAsString());
            if (tokens.has("error_description")) {
                System.out.println("Description: " + tokens.get("error_description").getAsString());
            }
            return;
        }
        
        System.out.println("\nSUCCESS! Tokens received:");
        System.out.println("  Access token: " + tokens.get("access_token").getAsString().substring(0, 30) + "...");
        if (tokens.has("refresh_token")) {
            System.out.println("  Refresh token: " + tokens.get("refresh_token").getAsString().substring(0, 30) + "...");
        }
        if (tokens.has("expires_in")) {
            System.out.println("  Expires in: " + tokens.get("expires_in").getAsInt() + " seconds");
        }
        
        // Extract account ID
        String accountId = extractAccountId(tokens);
        if (accountId != null) {
            System.out.println("  Account ID: " + accountId);
        }
        
        System.out.println("\nOAuth flow completed successfully!");
        System.out.println("You can now use these credentials in GhidrAssist.");
        
        // Output credentials JSON for GhidrAssist
        JsonObject credentials = new JsonObject();
        credentials.addProperty("access_token", tokens.get("access_token").getAsString());
        credentials.addProperty("refresh_token", tokens.has("refresh_token") ? tokens.get("refresh_token").getAsString() : "");
        credentials.addProperty("expires_at", System.currentTimeMillis() + (tokens.get("expires_in").getAsInt() * 1000L));
        if (accountId != null) {
            credentials.addProperty("account_id", accountId);
        }
        
        System.out.println("\nCredentials JSON (for GhidrAssist):");
        System.out.println(gson.toJson(credentials));
    }
    
    /**
     * Generate PKCE code verifier (43 chars, base64url encoded).
     */
    private static String generateCodeVerifier() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    /**
     * Generate PKCE code challenge from verifier using SHA-256.
     */
    private static String generateCodeChallenge(String verifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
    
    /**
     * Generate random state parameter for CSRF protection.
     */
    private static String generateState() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    /**
     * Build OAuth authorization URL with all required parameters.
     * Must match the Python implementation exactly.
     */
    private static String buildAuthorizeUrl(String challenge, String state) throws Exception {
        // Use StringBuilder with URLEncoder - matches Python's urlencode behavior
        StringBuilder params = new StringBuilder();
        params.append("response_type=code");
        params.append("&client_id=").append(URLEncoder.encode(CLIENT_ID, "UTF-8"));
        params.append("&redirect_uri=").append(URLEncoder.encode(REDIRECT_URI, "UTF-8"));
        params.append("&scope=").append(URLEncoder.encode(OAUTH_SCOPES, "UTF-8"));
        params.append("&code_challenge=").append(URLEncoder.encode(challenge, "UTF-8"));
        params.append("&code_challenge_method=S256");
        params.append("&state=").append(URLEncoder.encode(state, "UTF-8"));
        // Codex-specific parameters (from codex-cli-rs)
        params.append("&id_token_add_organizations=true");
        params.append("&codex_cli_simplified_flow=true");
        params.append("&originator=codex_cli_rs");
        
        return AUTH_URL + "?" + params.toString();
    }
    
    /**
     * Extract authorization code from user input.
     * Handles full URL, code#state format, or just the code.
     */
    private static String extractCode(String input) {
        // Try to parse as URL
        if (input.startsWith("http")) {
            try {
                URL url = URI.create(input).toURL();
                String query = url.getQuery();
                if (query != null) {
                    for (String param : query.split("&")) {
                        String[] pair = param.split("=", 2);
                        if (pair.length == 2 && "code".equals(pair[0])) {
                            System.out.println("Extracted code from URL");
                            return URLDecoder.decode(pair[1], "UTF-8");
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Failed to parse URL, using input as-is: " + e.getMessage());
            }
        }
        
        // Try code#state format
        if (input.contains("#")) {
            return input.split("#")[0];
        }
        
        // Return as-is
        return input;
    }
    
    /**
     * Exchange authorization code for tokens.
     * Uses form-encoded body (not JSON) as required by OpenAI.
     */
    private static JsonObject exchangeCodeForTokens(String code, String verifier) throws Exception {
        URL url = URI.create(TOKEN_URL).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);
        
        // Form-encoded body
        String body = "grant_type=authorization_code" +
                      "&code=" + URLEncoder.encode(code, "UTF-8") +
                      "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, "UTF-8") +
                      "&client_id=" + URLEncoder.encode(CLIENT_ID, "UTF-8") +
                      "&code_verifier=" + URLEncoder.encode(verifier, "UTF-8");
        
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }
        
        int responseCode = conn.getResponseCode();
        InputStream is = responseCode >= 400 ? conn.getErrorStream() : conn.getInputStream();
        
        String response;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            response = sb.toString();
        }
        
        if (responseCode >= 400) {
            System.out.println("Token exchange failed: " + responseCode);
            System.out.println("Response: " + response);
        }
        
        return gson.fromJson(response, JsonObject.class);
    }
    
    /**
     * Extract ChatGPT account ID from tokens.
     */
    private static String extractAccountId(JsonObject tokens) {
        // Try id_token first
        if (tokens.has("id_token")) {
            String accountId = extractAccountIdFromJwt(tokens.get("id_token").getAsString());
            if (accountId != null) return accountId;
        }
        
        // Fall back to access_token
        if (tokens.has("access_token")) {
            return extractAccountIdFromJwt(tokens.get("access_token").getAsString());
        }
        
        return null;
    }
    
    /**
     * Extract account ID from JWT claims.
     */
    private static String extractAccountIdFromJwt(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) return null;
            
            String payload = parts[1];
            // Add padding if needed
            int padding = 4 - payload.length() % 4;
            if (padding != 4) {
                payload += "=".repeat(padding);
            }
            
            byte[] decoded = Base64.getUrlDecoder().decode(payload);
            JsonObject claims = gson.fromJson(new String(decoded, StandardCharsets.UTF_8), JsonObject.class);
            
            // Direct claim
            if (claims.has("chatgpt_account_id")) {
                return claims.get("chatgpt_account_id").getAsString();
            }
            
            // Nested in auth namespace
            if (claims.has("https://api.openai.com/auth")) {
                JsonObject authNs = claims.getAsJsonObject("https://api.openai.com/auth");
                if (authNs.has("chatgpt_account_id")) {
                    return authNs.get("chatgpt_account_id").getAsString();
                }
            }
            
            // From organizations array
            if (claims.has("organizations") && claims.get("organizations").isJsonArray()) {
                var orgs = claims.getAsJsonArray("organizations");
                if (!orgs.isEmpty() && orgs.get(0).isJsonObject()) {
                    JsonObject firstOrg = orgs.get(0).getAsJsonObject();
                    if (firstOrg.has("id")) {
                        return firstOrg.get("id").getAsString();
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Failed to extract account ID: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Open URL in default browser.
     */
    private static void openBrowser(String url) {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            Runtime rt = Runtime.getRuntime();
            
            if (os.contains("mac")) {
                rt.exec(new String[]{"open", url});
            } else if (os.contains("win")) {
                rt.exec(new String[]{"rundll32", "url.dll,FileProtocolHandler", url});
            } else {
                rt.exec(new String[]{"xdg-open", url});
            }
        } catch (Exception e) {
            System.out.println("Could not open browser: " + e.getMessage());
            System.out.println("Please open the URL manually.");
        }
    }
}
