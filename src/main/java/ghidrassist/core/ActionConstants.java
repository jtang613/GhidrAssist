package ghidrassist.core;

import java.util.*;

public class ActionConstants {

    public static final List<Map<String, Object>> FN_TEMPLATES = Arrays.asList(
        createFunctionTemplate(
            "rename_function",
            "Rename a function",
            createParameters(
                createParameter("new_name", "string", "The new name for the function. (e.g., recv_data)")
            )
        ),
        createFunctionTemplate(
            "rename_variable",
            "Rename a variable within a function",
            createParameters(
                createParameter("func_name", "string", "The name of the function containing the variable. (e.g., sub_40001234)"),
                createParameter("var_name", "string", "The current name of the variable. (e.g., var_20)"),
                createParameter("new_name", "string", "The new name for the variable. (e.g., recv_buf)")
            )
        ),
        createFunctionTemplate(
            "retype_variable",
            "Set a variable data type within a function",
            createParameters(
                createParameter("func_name", "string", "The name of the function containing the variable. (e.g., sub_40001234)"),
                createParameter("var_name", "string", "The current name of the variable. (e.g., rax_12)"),
                createParameter("new_type", "string", "The new type for the variable. (e.g., int32_t)")
            )
        ),
        createFunctionTemplate(
            "auto_create_struct",
            "Automatically create a structure datatype from a variable given its offset uses in a given function.",
            createParameters(
                createParameter("func_name", "string", "The name of the function containing the variable. (e.g., sub_40001234)"),
                createParameter("var_name", "string", "The current name of the variable. (e.g., rax_12)")
            )
        )
    );

    public static final Map<String, String> ACTION_PROMPTS = new HashMap<>();

    static {
        ACTION_PROMPTS.put("rename_function",
            "Analyze this decompiled function and suggest better names:\n```\n{code}\n```\n" +
            "Consider the code functionality, strings, API calls, and log parameters.\n" +
            "For C++ methods, prefer Class::Method naming. Otherwise use descriptive procedural names.\n" +
            "Call the rename_function tool 3 times with your best name suggestions."
        );
        ACTION_PROMPTS.put("rename_variable",
            "Analyze this decompiled function and suggest better variable names:\n```\n{code}\n```\n" +
            "Consider the code functionality, how variables are used, and any contextual hints.\n" +
            "Call the rename_variable tool for each variable that would benefit from a clearer name."
        );
        ACTION_PROMPTS.put("retype_variable",
            "Analyze this decompiled function and suggest better variable types:\n```\n{code}\n```\n" +
            "Consider how variables are used, pointer arithmetic, and common type patterns.\n" +
            "Call the retype_variable tool for each variable that would benefit from a more accurate type."
        );
        ACTION_PROMPTS.put("auto_create_struct",
            "Analyze this decompiled function for structure/class usage:\n```\n{code}\n```\n" +
            "Look for variables with offset access patterns like `*(ptr + 0xc)` or field-like usage.\n" +
            "Call the auto_create_struct tool for each variable that appears to be a structure or class instance."
        );
    }

    // Helper methods for creating function templates
    private static Map<String, Object> createFunctionTemplate(String name, String description, Map<String, Object> parameters) {
        Map<String, Object> functionMap = new HashMap<>();
        functionMap.put("name", name);
        functionMap.put("description", description);
        functionMap.put("parameters", parameters);
        
        Map<String, Object> template = new HashMap<>();
        template.put("type", "function");
        template.put("function", functionMap);
        return template;
    }

    private static Map<String, Object> createParameters(Map<String, Object>... parameters) {
        Map<String, Object> parametersMap = new HashMap<>();
        parametersMap.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        List<String> required = new ArrayList<>();
        
        for (Map<String, Object> param : parameters) {
            String name = (String) param.get("name");
            properties.put(name, param);
            required.add(name);
        }
        
        parametersMap.put("properties", properties);
        parametersMap.put("required", required);
        return parametersMap;
    }

    private static Map<String, Object> createParameter(String name, String type, String description) {
        Map<String, Object> param = new HashMap<>();
        param.put("name", name);
        param.put("type", type);
        param.put("description", description);
        return param;
    }
}