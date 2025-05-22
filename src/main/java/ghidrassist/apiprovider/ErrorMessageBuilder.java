package ghidrassist.apiprovider;

import ghidrassist.apiprovider.exceptions.*;

/**
 * Builds user-friendly error messages from API provider exceptions
 */
public class ErrorMessageBuilder {
    
    /**
     * Build a user-friendly error message from an API provider exception
     */
    public static String buildUserMessage(APIProviderException e) {
        String baseMessage = buildBaseMessage(e);
        String suggestion = buildSuggestion(e);
        
        if (suggestion != null && !suggestion.isEmpty()) {
            return baseMessage + "\n\n" + suggestion;
        }
        
        return baseMessage;
    }
    
    /**
     * Build a short error message for status displays
     */
    public static String buildShortMessage(APIProviderException e) {
        return String.format("[%s] %s", e.getProviderName(), e.getCategory().getDisplayName());
    }
    
    private static String buildBaseMessage(APIProviderException e) {
        switch (e.getCategory()) {
            case AUTHENTICATION:
                return String.format("Authentication failed with %s. %s", 
                    e.getProviderName(), getAuthenticationDetails(e));
                    
            case NETWORK:
                return String.format("Connection failed to %s. %s", 
                    e.getProviderName(), getNetworkDetails(e));
                    
            case RATE_LIMIT:
                return String.format("Rate limit exceeded for %s. %s", 
                    e.getProviderName(), getRateLimitDetails(e));
                    
            case MODEL_ERROR:
                return String.format("Model error with %s. %s", 
                    e.getProviderName(), getModelDetails(e));
                    
            case CONFIGURATION:
                return String.format("Configuration error for %s. %s", 
                    e.getProviderName(), e.getMessage());
                    
            case RESPONSE_ERROR:
                return String.format("Invalid response from %s. %s", 
                    e.getProviderName(), getResponseDetails(e));
                    
            case SERVICE_ERROR:
                return String.format("Service error from %s. %s", 
                    e.getProviderName(), getServiceDetails(e));
                    
            case TIMEOUT:
                return String.format("Request to %s timed out. The operation took too long to complete.", 
                    e.getProviderName());
                    
            case CANCELLED:
                return String.format("Request to %s was cancelled. %s", 
                    e.getProviderName(), getCancellationDetails(e));
                    
            default:
                return String.format("Error with %s: %s", e.getProviderName(), e.getMessage());
        }
    }
    
    private static String buildSuggestion(APIProviderException e) {
        switch (e.getCategory()) {
            case AUTHENTICATION:
                return "Please check your API key in Settings. Verify the key is valid and has the necessary permissions.";
                
            case NETWORK:
                if (e instanceof NetworkException) {
                    NetworkException ne = (NetworkException) e;
                    if (ne.getNetworkErrorType() == NetworkException.NetworkErrorType.SSL_ERROR) {
                        return "Try enabling 'Disable TLS Verification' in Settings if using a local server.";
                    }
                }
                return "Check your internet connection and verify the API URL is correct.";
                
            case RATE_LIMIT:
                if (e.getRetryAfterSeconds() != null) {
                    return String.format("Please wait %d seconds before trying again, or consider switching to a different provider.", 
                        e.getRetryAfterSeconds());
                }
                return "Please wait a moment before trying again, or consider switching to a different provider.";
                
            case MODEL_ERROR:
                if (e instanceof ModelException) {
                    ModelException me = (ModelException) e;
                    if (me.getModelErrorType() == ModelException.ModelErrorType.MODEL_NOT_FOUND) {
                        return "Check that the model name is correct in Settings, or try a different model.";
                    } else if (me.getModelErrorType() == ModelException.ModelErrorType.CONTEXT_LENGTH_EXCEEDED) {
                        return "Try reducing the query length or use a model with a larger context window.";
                    }
                }
                return "Check your model settings and try a different model if available.";
                
            case CONFIGURATION:
                return "Please check your provider settings in the Settings dialog.";
                
            case RESPONSE_ERROR:
                return "This may be a temporary issue with the API. Try again in a moment.";
                
            case SERVICE_ERROR:
                return "The API service may be experiencing issues. Try again later or switch to a different provider.";
                
            case TIMEOUT:
                return "Try increasing the timeout value in Settings or check your connection speed.";
                
            case CANCELLED:
                return ""; // No suggestion needed for cancellations
                
            default:
                return "Please check your settings and try again.";
        }
    }
    
    private static String getAuthenticationDetails(APIProviderException e) {
        if (e.getHttpStatusCode() == 401) {
            return "Invalid or missing API key.";
        } else if (e.getHttpStatusCode() == 403) {
            return "API key does not have sufficient permissions.";
        }
        return e.getMessage() != null ? e.getMessage() : "Authentication failed.";
    }
    
    private static String getNetworkDetails(APIProviderException e) {
        if (e instanceof NetworkException) {
            NetworkException ne = (NetworkException) e;
            if (ne.getNetworkErrorType() != null) {
                return ne.getNetworkErrorType().getDescription();
            }
        }
        return e.getMessage() != null ? e.getMessage() : "Network connection failed.";
    }
    
    private static String getRateLimitDetails(APIProviderException e) {
        if (e.getRetryAfterSeconds() != null) {
            return String.format("Too many requests. Retry after %d seconds.", e.getRetryAfterSeconds());
        }
        return "Too many requests. Please wait before retrying.";
    }
    
    private static String getModelDetails(APIProviderException e) {
        if (e instanceof ModelException) {
            ModelException me = (ModelException) e;
            if (me.getModelErrorType() != null) {
                return me.getModelErrorType().getDescription();
            }
        }
        return e.getMessage() != null ? e.getMessage() : "Model error occurred.";
    }
    
    private static String getResponseDetails(APIProviderException e) {
        if (e instanceof ResponseException) {
            ResponseException re = (ResponseException) e;
            if (re.getResponseErrorType() != null) {
                return re.getResponseErrorType().getDescription();
            }
        }
        return e.getMessage() != null ? e.getMessage() : "Invalid response received.";
    }
    
    private static String getServiceDetails(APIProviderException e) {
        if (e.getHttpStatusCode() >= 500) {
            return "The API service is experiencing internal issues.";
        } else if (e.getHttpStatusCode() == 503) {
            return "The API service is temporarily unavailable.";
        }
        return e.getMessage() != null ? e.getMessage() : "Service error occurred.";
    }
    
    private static String getCancellationDetails(APIProviderException e) {
        if (e instanceof StreamCancelledException) {
            StreamCancelledException sce = (StreamCancelledException) e;
            return sce.getCancellationReason().getDescription();
        }
        return e.getMessage() != null ? e.getMessage() : "Request was cancelled.";
    }
}