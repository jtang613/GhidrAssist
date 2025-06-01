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
			"Use the 'rename_function' tool:\n```\n{code}\n```\n" +
            "Examine the code functionality, strings and log parameters.\n" +
            "If you detect C++ Super::Derived::Method or Class::Method style class names, recommend that name first, OTHERWISE USE PROCEDURAL NAMING.\n" +
            "CREATE A JSON TOOL_CALL LIST WITH SUGGESTIONS FOR THREE POSSIBLE FUNCTION NAMES " +
            "THAT ALIGN AS CLOSELY AS POSSIBLE TO WHAT THE CODE ABOVE DOES.\n" +
            "RESPOND ONLY WITH THE RENAME_FUNCTION PARAMETER (new_name). DO NOT INCLUDE ANY OTHER TEXT.\n" +
            "ALL JSON MUST BE PROPERLY FORMATTED WITH NO EMBEDDED COMMENTS.\n"
        );
        ACTION_PROMPTS.put("rename_variable",
            "Use the 'rename_variable' tool:\n```\n{code}\n```\n" +
            "Examine the code functionality, strings, and log parameters.\n" +
            "SUGGEST VARIABLE NAMES THAT BETTER ALIGN WITH THE CODE FUNCTIONALITY.\n" +
            "RESPOND ONLY WITH THE RENAME_VARIABLE PARAMETERS (func_name, var_name, new_name). DO NOT INCLUDE ANY OTHER TEXT.\n" +
            "ALL JSON VALUES MUST BE TEXT STRINGS, INCLUDING NUMBERS AND ADDRESSES, e.g., \"0x1234abcd\".\n" +
            "ALL JSON MUST BE PROPERLY FORMATTED WITH NO EMBEDDED COMMENTS.\n"
        );
        ACTION_PROMPTS.put("retype_variable",
            "Use the 'retype_variable' tool:\n```\n{code}\n```\n" +
            "Examine the code functionality, strings, and log parameters.\n" +
            "SUGGEST VARIABLE TYPES THAT BETTER ALIGN WITH THE CODE FUNCTIONALITY.\n" +
            "RESPOND ONLY WITH THE RETYPE_VARIABLE PARAMETERS (func_name, var_name, new_type). DO NOT INCLUDE ANY OTHER TEXT.\n" +
            "ALL JSON VALUES MUST BE TEXT STRINGS, INCLUDING NUMBERS AND ADDRESSES, e.g., \"0x1234abcd\".\n" +
            "ALL JSON MUST BE PROPERLY FORMATTED WITH NO EMBEDDED COMMENTS.\n"
        );
        ACTION_PROMPTS.put("auto_create_struct",
            "Use the 'auto_create_struct' tool:\n```\n{code}\n```\n" +
            "Examine the code functionality, parameters, and variables being used.\n" +
            "IF YOU DETECT A VARIABLE THAT USES OFFSET ACCESS SUCH AS `*(arg1 + 0xc)` OR VARIABLES LIKELY TO BE STRUCTURES OR CLASSES,\n" +
            "RESPOND ONLY WITH THE AUTO_CREATE_STRUCT PARAMETERS (func_name, var_name). DO NOT INCLUDE ANY OTHER TEXT.\n" +
            "ALL JSON VALUES MUST BE TEXT STRINGS, INCLUDING NUMBERS AND ADDRESSES, e.g., \"0x1234abcd\".\n" +
            "ALL JSON MUST BE PROPERLY FORMATTED WITH NO EMBEDDED COMMENTS.\n"
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