package ghidrassist.apiprovider.exceptions;

/**
 * Exception for model-related errors
 */
public class ModelException extends APIProviderException {
    
    public enum ModelErrorType {
        MODEL_NOT_FOUND("The specified model was not found or is not available"),
        UNSUPPORTED_FEATURE("The model does not support this feature"),
        CONTEXT_LENGTH_EXCEEDED("Input exceeds the model's maximum context length"),
        TOKEN_LIMIT_EXCEEDED("Response would exceed the maximum token limit"),
        MODEL_OVERLOADED("The model is currently overloaded");
        
        private final String description;
        
        ModelErrorType(String description) {
            this.description = description;
        }
        
        public String getDescription() { return description; }
    }
    
    private final ModelErrorType modelErrorType;
    
    public ModelException(String providerName, String operation, ModelErrorType errorType) {
        super(ErrorCategory.MODEL_ERROR, providerName, operation, errorType.getDescription());
        this.modelErrorType = errorType;
    }
    
    public ModelException(String providerName, String operation, ModelErrorType errorType,
                        int httpStatusCode, String apiErrorCode) {
        super(ErrorCategory.MODEL_ERROR, providerName, operation, httpStatusCode, apiErrorCode,
              errorType.getDescription(), false, null, null);
        this.modelErrorType = errorType;
    }
    
    public ModelException(String providerName, String operation, String message) {
        super(ErrorCategory.MODEL_ERROR, providerName, operation, message);
        this.modelErrorType = null;
    }
    
    public ModelErrorType getModelErrorType() {
        return modelErrorType;
    }
}