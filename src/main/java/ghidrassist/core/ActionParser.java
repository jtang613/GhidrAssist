package ghidrassist.core;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import javax.swing.table.DefaultTableModel;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;

public class ActionParser {
    private static final Gson gson = new Gson();
    
    /**
     * Parse the LLM response and display actions in the table model.
     * @param response Raw response from LLM
     * @param model Table model to populate
     * @throws Exception if parsing fails
     */
    public static void parseAndDisplay(String response, DefaultTableModel model) throws Exception {
        String jsonStr = preprocessJsonResponse(response);
        JsonObject jsonObject = parseJson(jsonStr);
        
        if (!jsonObject.has("tool_calls")) {
            throw new Exception("Response does not contain 'tool_calls' field");
        }
        
        JsonArray toolCallsArray = jsonObject.getAsJsonArray("tool_calls");
        processToolCalls(toolCallsArray, model);
    }
    
    /**
     * Preprocess the response to extract JSON from potential code blocks.
     */
    private static String preprocessJsonResponse(String response) {
        String json = response.trim();

        // Define regex patterns to match code block markers
        Pattern codeBlockPattern = Pattern.compile("(?s)^[`']{3}(\\w+)?\\s*(.*?)\\s*[`']{3}$");
        Matcher matcher = codeBlockPattern.matcher(json);

        if (matcher.find()) {
            // Extract the content inside the code block
            json = matcher.group(2).trim();
        } else {
            // If no code block markers, attempt to find the JSON content directly
            // Remove any leading or trailing quotes
            if ((json.startsWith("\"") && json.endsWith("\"")) || 
                (json.startsWith("'") && json.endsWith("'"))) {
                json = json.substring(1, json.length() - 1).trim();
            }
        }
        json = json.replace("\\n", "").replace("\\", "");
        return json;
    }
    
    /**
     * Parse JSON string into JsonObject with lenient parsing.
     */
    private static JsonObject parseJson(String jsonStr) throws JsonSyntaxException {
        JsonReader jsonReader = new JsonReader(new StringReader(jsonStr));
        jsonReader.setLenient(true);
        JsonElement jsonElement = gson.fromJson(jsonReader, JsonElement.class);
        
        if (!jsonElement.isJsonObject()) {
            throw new JsonSyntaxException("Unexpected JSON structure in response");
        }
        
        return jsonElement.getAsJsonObject();
    }
    
    /**
     * Process tool calls array and populate table model.
     */
    private static void processToolCalls(JsonArray toolCallsArray, DefaultTableModel model) {
        // Get list of valid function names
        List<String> validFunctions = new ArrayList<>();
        for (Map<String, Object> fnTemplate : ToolCalling.FN_TEMPLATES) {
            @SuppressWarnings("unchecked")
            Map<String, Object> functionMap = (Map<String, Object>) fnTemplate.get("function");
            validFunctions.add(functionMap.get("name").toString());
        }
        
        // Process each tool call
        for (JsonElement toolCallElement : toolCallsArray) {
            if (!toolCallElement.isJsonObject()) {
                continue;
            }
            
            JsonObject toolCallObject;
            if (toolCallElement.getAsJsonObject().has("function")) {
            	toolCallObject = toolCallElement.getAsJsonObject().get("function").getAsJsonObject();
            } else {
            	toolCallObject = toolCallElement.getAsJsonObject();
            }
            
            // Validate tool call has required fields
            if (!toolCallObject.has("name") || !toolCallObject.has("arguments")) {
                continue;
            }
            
            String functionName = toolCallObject.get("name").getAsString();
            JsonObject arguments = toolCallObject.getAsJsonObject("arguments");
            
            // Skip if function is not in our templates
            if (!validFunctions.contains(functionName)) {
                continue;
            }
            
            // Add to actions table
            Object[] rowData = new Object[]{
                Boolean.FALSE,  // Initially unchecked
                functionName.replace("_", " "),
                formatDescription(functionName, arguments),
                "",  // Status
                arguments.toString()  // Store full arguments JSON
            };
            model.addRow(rowData);
        }
    }
    
    /**
     * Format the description based on action type and arguments.
     */
    private static String formatDescription(String functionName, JsonObject arguments) {
        try {
            switch (functionName) {
                case "rename_function":
                    return arguments.get("new_name").getAsString();
                    
                case "rename_variable":
                    return arguments.get("var_name").getAsString() + " -> " + 
                           arguments.get("new_name").getAsString();
                    
                case "retype_variable":
                    return arguments.get("var_name").getAsString() + " -> " + 
                           arguments.get("new_type").getAsString();
                    
                case "auto_create_struct":
                    return arguments.get("var_name").getAsString();
                    
                default:
                    return "";
            }
        } catch (Exception e) {
            return "Error: Failed to parse arguments";
        }
    }
}
