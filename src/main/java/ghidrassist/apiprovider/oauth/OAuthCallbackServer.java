package ghidrassist.apiprovider.oauth;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Local HTTP server for receiving OAuth callbacks from OAuth authorization flows.
 * 
 * This server listens on a configured port (with fallback) and waits for the OAuth 
 * redirect with the authorization code. It validates the state parameter to prevent 
 * CSRF attacks.
 * 
 * Supports both Anthropic (port 1456, /callback) and OpenAI (port 1455, /auth/callback).
 */
public class OAuthCallbackServer {
    
    // Default ports for OAuth providers
    public static final int OPENAI_DEFAULT_PORT = 1455;
    public static final int ANTHROPIC_DEFAULT_PORT = 1456;
    private static final int PORT_FALLBACK_RANGE = 5;
    
    private static final String SUCCESS_HTML = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Successful - GhidrAssist</title>
            <meta charset="utf-8">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    padding: 50px 40px;
                    border-radius: 16px;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                    text-align: center;
                    max-width: 450px;
                    width: 100%%;
                }
                .checkmark {
                    width: 80px;
                    height: 80px;
                    background: linear-gradient(135deg, #4CAF50 0%%, #45a049 100%%);
                    border-radius: 50%%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 25px;
                    box-shadow: 0 4px 15px rgba(76, 175, 80, 0.4);
                }
                .checkmark svg {
                    width: 40px;
                    height: 40px;
                    fill: white;
                }
                h1 {
                    color: #1a1a2e;
                    font-size: 24px;
                    font-weight: 600;
                    margin-bottom: 12px;
                }
                .provider {
                    color: #667eea;
                    font-weight: 600;
                }
                p {
                    color: #666;
                    font-size: 16px;
                    line-height: 1.6;
                    margin-bottom: 8px;
                }
                .hint {
                    color: #999;
                    font-size: 14px;
                    margin-top: 20px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                }
                .app-name {
                    color: #764ba2;
                    font-weight: 600;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="checkmark">
                    <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
                    </svg>
                </div>
                <h1>Authentication Successful</h1>
                <p>You have successfully authenticated.</p>
                <p class="hint">You can close this tab and return to <span class="app-name">Ghidra</span>.</p>
            </div>
        </body>
        </html>
        """;
    
    private static final String ERROR_HTML = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Failed - GhidrAssist</title>
            <meta charset="utf-8">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                    background: linear-gradient(135deg, #e74c3c 0%%, #c0392b 100%%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    padding: 50px 40px;
                    border-radius: 16px;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                    text-align: center;
                    max-width: 450px;
                    width: 100%%;
                }
                .error-icon {
                    width: 80px;
                    height: 80px;
                    background: linear-gradient(135deg, #e74c3c 0%%, #c0392b 100%%);
                    border-radius: 50%%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 25px;
                    box-shadow: 0 4px 15px rgba(231, 76, 60, 0.4);
                }
                .error-icon svg {
                    width: 40px;
                    height: 40px;
                    fill: white;
                }
                h1 {
                    color: #1a1a2e;
                    font-size: 24px;
                    font-weight: 600;
                    margin-bottom: 12px;
                }
                p {
                    color: #666;
                    font-size: 16px;
                    line-height: 1.6;
                    margin-bottom: 8px;
                }
                .error-details {
                    background: #fff5f5;
                    border: 1px solid #feb2b2;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 20px 0;
                    color: #c53030;
                    font-size: 14px;
                    word-break: break-word;
                }
                .hint {
                    color: #999;
                    font-size: 14px;
                    margin-top: 20px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">
                    <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                    </svg>
                </div>
                <h1>Authentication Failed</h1>
                <p>An error occurred during authentication.</p>
                <div class="error-details">%s</div>
                <p class="hint">Please close this tab and try again in Ghidra.</p>
            </div>
        </body>
        </html>
        """;
    
    private HttpServer server;
    private int port;
    private final CompletableFuture<String> authCodeFuture;
    private final String expectedState;
    private final String callbackPath;
    private final int preferredPort;
    private final boolean validateState;
    
    /**
     * Creates a new OAuth callback server with default settings.
     * Uses dynamic port allocation and /callback path.
     * 
     * @param expectedState The state parameter to validate against CSRF attacks
     */
    public OAuthCallbackServer(String expectedState) {
        this(expectedState, "/callback", 0, true);
    }
    
    /**
     * Creates a new OAuth callback server with custom configuration.
     * 
     * @param expectedState The state parameter to validate against CSRF attacks
     * @param callbackPath The path for the callback endpoint (e.g., "/callback" or "/auth/callback")
     * @param preferredPort The preferred port to use (0 for dynamic allocation)
     * @param validateState Whether to validate the state parameter
     */
    public OAuthCallbackServer(String expectedState, String callbackPath, int preferredPort, boolean validateState) {
        this.expectedState = expectedState;
        this.callbackPath = callbackPath;
        this.preferredPort = preferredPort;
        this.validateState = validateState;
        this.authCodeFuture = new CompletableFuture<>();
    }
    
    /**
     * Creates an OAuth callback server configured for OpenAI OAuth.
     * Uses port 1455 with /auth/callback path.
     * 
     * @param expectedState The state parameter to validate against CSRF attacks
     * @return A configured OAuthCallbackServer for OpenAI
     */
    public static OAuthCallbackServer forOpenAI(String expectedState) {
        return new OAuthCallbackServer(expectedState, "/auth/callback", OPENAI_DEFAULT_PORT, true);
    }
    
    /**
     * Creates an OAuth callback server configured for Anthropic OAuth.
     * Uses port 1456 with /callback path.
     * 
     * @param expectedState The state parameter to validate against CSRF attacks
     * @return A configured OAuthCallbackServer for Anthropic
     */
    public static OAuthCallbackServer forAnthropic(String expectedState) {
        return new OAuthCallbackServer(expectedState, "/callback", ANTHROPIC_DEFAULT_PORT, true);
    }
    
    /**
     * Starts the callback server on the preferred port (with fallback).
     * 
     * @return The port number the server is listening on
     * @throws IOException If the server cannot be started on any port
     */
    public int start() throws IOException {
        if (preferredPort > 0) {
            // Try preferred port first, then fallback ports
            port = findAvailablePortWithFallback(preferredPort);
        } else {
            // Dynamic port allocation
            port = findAvailablePort();
        }
        
        // Create and configure the server
        server = HttpServer.create(new InetSocketAddress("localhost", port), 0);
        server.createContext(callbackPath, this::handleCallback);
        server.setExecutor(null); // Use default executor
        server.start();
        
        Msg.info(this, "OAuth callback server started on port " + port + " with path " + callbackPath);
        return port;
    }
    
    /**
     * Waits for the authorization code with a timeout.
     * 
     * @param timeoutMinutes Timeout in minutes
     * @return The authorization code
     * @throws Exception If the wait times out or an error occurs
     */
    public String waitForCode(int timeoutMinutes) throws Exception {
        try {
            return authCodeFuture.get(timeoutMinutes, TimeUnit.MINUTES);
        } finally {
            // Delay stop to allow the success HTML page to be fully sent to browser
            stopDelayed(1);
        }
    }
    
    /**
     * Gets the future that will be completed with the authorization code.
     * 
     * @return The CompletableFuture for the authorization code
     */
    public CompletableFuture<String> getAuthCodeFuture() {
        return authCodeFuture;
    }
    
    /**
     * Stops the callback server immediately.
     */
    public void stop() {
        stopDelayed(0);
    }
    
    /**
     * Stops the callback server with a delay to allow pending responses to complete.
     * 
     * @param delaySeconds Seconds to wait for pending exchanges to finish
     */
    public void stopDelayed(int delaySeconds) {
        if (server != null) {
            server.stop(delaySeconds);
            server = null;
            Msg.info(this, "OAuth callback server stopped");
        }
    }
    
    /**
     * Gets the port the server is listening on.
     * 
     * @return The port number
     */
    public int getPort() {
        return port;
    }
    
    /**
     * Gets the redirect URI for this server.
     * 
     * @return The redirect URI (e.g., "http://localhost:12345/callback")
     */
    public String getRedirectUri() {
        return "http://localhost:" + port + callbackPath;
    }
    
    /**
     * Finds a dynamic available port for the callback server.
     */
    private int findAvailablePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        }
    }
    
    /**
     * Tries to find an available port starting from the preferred port.
     * Falls back to subsequent ports if the preferred port is unavailable.
     * 
     * @param preferred The preferred port to start with
     * @return An available port
     * @throws IOException If no port in the range is available
     */
    private int findAvailablePortWithFallback(int preferred) throws IOException {
        for (int i = 0; i <= PORT_FALLBACK_RANGE; i++) {
            int testPort = preferred + i;
            if (isPortAvailable(testPort)) {
                if (i > 0) {
                    Msg.info(this, "Preferred port " + preferred + " unavailable, using port " + testPort);
                }
                return testPort;
            }
        }
        // Fall back to dynamic allocation if all preferred ports are taken
        Msg.warn(this, "All preferred ports (" + preferred + "-" + (preferred + PORT_FALLBACK_RANGE) + 
                      ") unavailable, using dynamic port");
        return findAvailablePort();
    }
    
    /**
     * Checks if a specific port is available.
     */
    private boolean isPortAvailable(int testPort) {
        try (ServerSocket socket = new ServerSocket(testPort)) {
            socket.setReuseAddress(true);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
    
    /**
     * Handles the OAuth callback request.
     */
    private void handleCallback(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        String response;
        int statusCode;
        
        try {
            // Parse query parameters
            String code = null;
            String state = null;
            String error = null;
            String errorDescription = null;
            
            if (query != null) {
                for (String param : query.split("&")) {
                    String[] pair = param.split("=", 2);
                    if (pair.length == 2) {
                        String key = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
                        switch (key) {
                            case "code" -> code = value;
                            case "state" -> state = value;
                            case "error" -> error = value;
                            case "error_description" -> errorDescription = value;
                        }
                    }
                }
            }
            
            // Check for OAuth error
            if (error != null) {
                String errorMsg = errorDescription != null ? errorDescription : error;
                throw new OAuthException("OAuth error: " + errorMsg);
            }
            
            // Validate code is present
            if (code == null || code.isEmpty()) {
                throw new OAuthException("No authorization code received");
            }
            
            // Validate state parameter to prevent CSRF (if enabled)
            if (validateState && (state == null || !state.equals(expectedState))) {
                throw new OAuthException("State mismatch - possible CSRF attack");
            }
            
            // Success - complete the future with the authorization code
            authCodeFuture.complete(code);
            response = SUCCESS_HTML;
            statusCode = 200;
            
            Msg.info(this, "OAuth callback received authorization code");
            
        } catch (OAuthException e) {
            // Error - complete the future exceptionally
            authCodeFuture.completeExceptionally(e);
            response = String.format(ERROR_HTML, escapeHtml(e.getMessage()));
            statusCode = 400;
            
            Msg.error(this, "OAuth callback error: " + e.getMessage());
        }
        
        // Send response
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
    
    /**
     * Escapes HTML special characters.
     */
    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
    
    /**
     * Exception for OAuth-related errors.
     */
    public static class OAuthException extends Exception {
        private static final long serialVersionUID = 1L;

        public OAuthException(String message) {
            super(message);
        }
        
        public OAuthException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
