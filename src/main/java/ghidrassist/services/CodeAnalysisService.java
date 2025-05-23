package ghidrassist.services;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.core.CodeUtils;

/**
 * Service for handling code analysis operations.
 * Responsible for explaining functions and lines of code.
 */
public class CodeAnalysisService {
    
    private final GhidrAssistPlugin plugin;
    private final AnalysisDB analysisDB;
    
    public CodeAnalysisService(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.analysisDB = new AnalysisDB();
    }
    
    /**
     * Analyze and explain a function
     */
    public AnalysisRequest createFunctionAnalysisRequest(Function function) throws Exception {
        if (function == null) {
            throw new IllegalArgumentException("No function at current location.");
        }
        
        String functionCode = null;
        String codeType = null;
        
        GhidrAssistPlugin.CodeViewType viewType = plugin.checkLastActiveCodeView();
        if (viewType == GhidrAssistPlugin.CodeViewType.IS_DECOMPILER) {
            functionCode = CodeUtils.getFunctionCode(function, TaskMonitor.DUMMY);
            codeType = "pseudo-C";
        } else if (viewType == GhidrAssistPlugin.CodeViewType.IS_DISASSEMBLER) {
            functionCode = CodeUtils.getFunctionDisassembly(function);
            codeType = "assembly";
        } else {
            throw new Exception("Unknown code view type.");
        }
        
        String prompt = "Explain the following " + codeType + " code:\n```\n" + functionCode + "\n```";
        return new AnalysisRequest(AnalysisRequest.Type.FUNCTION, prompt, function);
    }
    
    /**
     * Analyze and explain a line of code
     */
    public AnalysisRequest createLineAnalysisRequest(Address address) throws Exception {
        if (address == null) {
            throw new IllegalArgumentException("No address at current location.");
        }
        
        String codeLine = null;
        String codeType = null;
        
        GhidrAssistPlugin.CodeViewType viewType = plugin.checkLastActiveCodeView();
        if (viewType == GhidrAssistPlugin.CodeViewType.IS_DECOMPILER) {
            codeLine = CodeUtils.getLineCode(address, TaskMonitor.DUMMY, plugin.getCurrentProgram());
            codeType = "pseudo-C";
        } else if (viewType == GhidrAssistPlugin.CodeViewType.IS_DISASSEMBLER) {
            codeLine = CodeUtils.getLineDisassembly(address, plugin.getCurrentProgram());
            codeType = "assembly";
        } else {
            throw new Exception("Unknown code view type.");
        }
        
        String prompt = "Explain the following " + codeType + " line:\n```\n" + codeLine + "\n```";
        return new AnalysisRequest(AnalysisRequest.Type.LINE, prompt, address);
    }
    
    /**
     * Execute an analysis request
     */
    public void executeAnalysis(AnalysisRequest request, LlmApi.LlmResponseHandler handler) throws Exception {
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            throw new Exception("No API provider configured.");
        }
        
        LlmApi llmApi = new LlmApi(config, plugin);
        llmApi.sendRequestAsync(request.getPrompt(), handler);
    }
    
    /**
     * Store analysis result in database
     */
    public void storeAnalysisResult(Function function, String prompt, String response) {
        if (function != null && plugin.getCurrentProgram() != null) {
            analysisDB.upsertAnalysis(
                plugin.getCurrentProgram().getExecutableSHA256(),
                function.getEntryPoint(),
                prompt,
                response
            );
        }
    }
    
    /**
     * Get existing analysis for a function
     */
    public AnalysisDB.Analysis getExistingAnalysis(Function function) {
        if (function == null || plugin.getCurrentProgram() == null) {
            return null;
        }
        
        return analysisDB.getAnalysis(
            plugin.getCurrentProgram().getExecutableSHA256(),
            function.getEntryPoint()
        );
    }
    
    /**
     * Update existing analysis
     */
    public void updateAnalysis(Function function, String updatedContent) {
        if (function == null || plugin.getCurrentProgram() == null) {
            throw new IllegalArgumentException("No active program or function");
        }
        
        String programHash = plugin.getCurrentProgram().getExecutableSHA256();
        Address functionAddress = function.getEntryPoint();
        
        // Get existing analysis to preserve the query
        AnalysisDB.Analysis existingAnalysis = analysisDB.getAnalysis(programHash, functionAddress);
        
        if (existingAnalysis == null) {
            // Create new entry with generic query
            analysisDB.upsertAnalysis(programHash, functionAddress, "Edited explanation", updatedContent);
        } else {
            // Update existing entry, preserving original query
            analysisDB.upsertAnalysis(programHash, functionAddress, existingAnalysis.getQuery(), updatedContent);
        }
    }
    
    /**
     * Clear analysis data for a function
     */
    public boolean clearAnalysis(Function function) {
        if (function == null || plugin.getCurrentProgram() == null) {
            return false;
        }
        
        String programHash = plugin.getCurrentProgram().getExecutableSHA256();
        Address functionAddress = function.getEntryPoint();
        
        return analysisDB.deleteAnalysis(programHash, functionAddress);
    }
    
    /**
     * Close database resources
     */
    public void close() {
        if (analysisDB != null) {
            analysisDB.close();
        }
    }
    
    /**
     * Request object for analysis operations
     */
    public static class AnalysisRequest {
        public enum Type {
            FUNCTION, LINE
        }
        
        private final Type type;
        private final String prompt;
        private final Object context; // Function or Address
        
        public AnalysisRequest(Type type, String prompt, Object context) {
            this.type = type;
            this.prompt = prompt;
            this.context = context;
        }
        
        public Type getType() { return type; }
        public String getPrompt() { return prompt; }
        public Object getContext() { return context; }
        
        public Function getFunction() {
            return context instanceof Function ? (Function) context : null;
        }
        
        public Address getAddress() {
            return context instanceof Address ? (Address) context : null;
        }
    }
}