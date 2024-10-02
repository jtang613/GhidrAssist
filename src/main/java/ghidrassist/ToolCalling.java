package ghidrassist;

import java.util.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.program.model.address.*;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class ToolCalling {

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

    @SafeVarargs
	private static Map<String, Object> createParameters(Map<String, Object>... params) {
        Map<String, Object> properties = new LinkedHashMap<>();
        for (Map<String, Object> param : params) {
            properties.put((String) param.get("name"), param);
        }
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("type", "object");
        parameters.put("properties", properties);
        List<String> required = new ArrayList<>();
        for (Map<String, Object> param : params) {
            required.add((String) param.get("name"));
        }
        parameters.put("required", required);
        return parameters;
    }

    private static Map<String, Object> createParameter(String name, String type, String description) {
        Map<String, Object> param = new HashMap<>();
        param.put("name", name);
        param.put("type", type);
        param.put("description", description);
        return param;
    }

    // Handler methods for each action
    public static void handle_rename_function(Program program, Address address, String newName) throws InvalidInputException, DuplicateNameException {
    	int transaction = program.startTransaction("Rename Function");
        boolean success = false;
    	FunctionManager functionManager = program.getFunctionManager();
        Function function = functionManager.getFunctionContaining(address);
        if (function != null) {
            function.setName(newName, SourceType.USER_DEFINED);
            success = true;
        } else {
            program.endTransaction(transaction, success);
            throw new InvalidInputException("Function not found at address: " + address.toString());
        }
        program.endTransaction(transaction, success);
    }

    public static void handle_rename_variable(Program program, Address address, String funcName, String varName, String newName) throws InvalidInputException, DuplicateNameException {
    	int transaction = program.startTransaction("Rename Variable");
        boolean success = false;
        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
        	program.endTransaction(transaction, success);
            throw new InvalidInputException("Function not found: " + funcName);
        }
        // Combine variables from getAllVariables() and getLocalVariables()
        commitLocalNames(program, function);
        List<Variable> combinedVariables = new ArrayList<>(Arrays.asList(function.getAllVariables()));
        combinedVariables.addAll(Arrays.asList(function.getAllVariables())); // Locals
        combinedVariables.addAll(Arrays.asList(function.getParameters()));  // Parameters

        // Search for the variable by name in the combined list
        for (Variable var : combinedVariables) {
            if (var.getName().equals(varName)) {
                var.setName(newName, SourceType.USER_DEFINED);
                success = true;
                break;
            }
        }
        if (success == false) {
	        throw new InvalidInputException("Variable not found: " + varName);
        }
        program.endTransaction(transaction, success);
    }

    public static void handle_retype_variable(Program program, Address address, String funcName, String varName, String newTypeStr) throws InvalidDataTypeException, CancelledException, InvalidInputException, DuplicateNameException {
        int transaction = program.startTransaction("Retype Variable");
        boolean success = false;
        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
        	program.endTransaction(transaction, success);
            throw new InvalidInputException("Function not found: " + funcName);
        }
        // Combine variables from getAllVariables() and getLocalVariables()
        commitLocalNames(program, function);
        List<Variable> combinedVariables = new ArrayList<>(Arrays.asList(function.getAllVariables()));
        combinedVariables.addAll(Arrays.asList(function.getAllVariables())); // Locals
        combinedVariables.addAll(Arrays.asList(function.getParameters()));  // Parameters

        // Search for the variable by name in the combined list
        for (Variable var : combinedVariables) {
            if (var.getName().equals(varName)) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType newType = getDataType(newTypeStr, dtm, program);
                if (newType != null) {
                    var.setDataType(newType, true, true, SourceType.USER_DEFINED);
                    success = true;
                    break;
                } else {
                    program.endTransaction(transaction, success);
                    throw new InvalidDataTypeException("Failed to parse data type: " + newTypeStr);
                }
            }
        }
        if (!success) {
        	program.endTransaction(transaction, success);
            throw new InvalidInputException("Variable not found: " + varName);
        }
        program.endTransaction(transaction, success);
    }

    private static DataType getDataType(String dataTypeStr, DataTypeManager dtm, Program program) throws InvalidDataTypeException, CancelledException {
        // First, try to get the data type directly
        DataType dataType = dtm.getDataType(new CategoryPath("/"), dataTypeStr);
        
        // If not found, try to parse it
        if (dataType == null) {
        	DataTypeParser parser = new DataTypeParser(dtm, program.getDataTypeManager(), null, DataTypeParser.AllowedDataTypes.ALL);
            dataType = parser.parse(dataTypeStr);
        }
        
        return dataType;
    }

    public static void handle_auto_create_struct(Program program, Address address, String funcName, String varName) throws InvalidInputException, DuplicateNameException, CancelledException {
        int transaction = program.startTransaction("Auto Create Struct");
        boolean success = false;

        try {
            // Retrieve the function at the specified address
            Function function = program.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                throw new InvalidInputException("Function not found: " + funcName);
            }
            
            // Combine variables from getAllVariables() and getParameters()
            commitLocalNames(program, function);
            List<Variable> combinedVariables = new ArrayList<>();
            combinedVariables.addAll(Arrays.asList(function.getAllVariables()));
            combinedVariables.addAll(Arrays.asList(function.getParameters())); // Parameters

            // Decompile the function
            DecompInterface decompiler = new DecompInterface();
            DecompileOptions options = new DecompileOptions();
            options.grabFromProgram(program);
            decompiler.setOptions(options);
            decompiler.openProgram(program);
            DecompileResults decompileResults = decompiler.decompileFunction(function, 30, null);

            if (!decompileResults.decompileCompleted()) {
                throw new InvalidInputException("Decompilation failed for function: " + funcName);
            }

            HighFunction highFunction = decompileResults.getHighFunction();

            // Find the HighVariable for varName
            HighVariable highVar = findHighVariable(highFunction, varName);
            if (highVar == null) {
                throw new InvalidInputException("Variable not found: " + varName);
            }

            // Use FillOutStructureHelper
            TaskMonitor monitor = TaskMonitor.DUMMY;
            FillOutStructureHelper fillHelper = new FillOutStructureHelper(program, options, monitor);
            Structure structDT = fillHelper.processStructure(highVar, function, false, true);

            if (structDT == null) {
                throw new InvalidInputException("Failed to create structure for variable: " + varName);
            }

            // Add the struct to the DataTypeManager
            DataTypeManager dtm = program.getDataTypeManager();
            structDT = (Structure) dtm.addDataType(structDT, DataTypeConflictHandler.DEFAULT_HANDLER);

            // Create a pointer to the struct
            PointerDataType ptrStruct = new PointerDataType(structDT);

            // Apply the data type to the variable
            Variable var = null;
            for (Variable v : combinedVariables) {
                if (v.getName().equals(varName)) {
                    var = v;
                    break;
                }
            }
            
            if (var != null && var instanceof AutoParameterImpl) {
                // Modify the function signature to change the data type of the auto-parameter
                Parameter[] parameters = function.getParameters();
                Parameter[] newParams = new Parameter[parameters.length];

                for (int i = 0; i < parameters.length; i++) {
                    if (parameters[i].getName().equals(varName)) {
                        newParams[i] = new ParameterImpl(
                            parameters[i].getName(),
                            ptrStruct,
                            parameters[i].getVariableStorage(),
                            program,
                            SourceType.USER_DEFINED
                        );
                    } else {
                        newParams[i] = parameters[i];
                    }
                }

                // Update the function signature
                function.updateFunction(
                    function.getCallingConventionName(),
                    null, // Return type remains the same
                    FunctionUpdateType.CUSTOM_STORAGE,
                    true, // Force the update
                    SourceType.USER_DEFINED,
                    newParams
                );
            } else {
                // Update local variable
                HighFunctionDBUtil.updateDBVariable(highVar.getSymbol(), null, ptrStruct, SourceType.USER_DEFINED);
            }

            success = true;

        } catch (Exception e) {
            throw new InvalidInputException("Error in auto-creating struct: " + e.getMessage());
        } finally {
            program.endTransaction(transaction, success);
        }
    }

    private static HighVariable findHighVariable(HighFunction highFunction, String varName) {
        // Retrieve all high-level variables from the function and search by name
        Iterator<HighSymbol> highVariables = highFunction.getLocalSymbolMap().getSymbols();
        while (highVariables.hasNext()) {
        	HighSymbol highVar = highVariables.next(); 
            if (highVar.getName().equals(varName)) {
                return highVar.getHighVariable();
            }
        }
        return null;
    }

    public static void commitLocalNames(Program program, Function function) {
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(program);
        
        DecompileResults res = ifc.decompileFunction(function, 30, null);
        if (res.decompileCompleted()) {
            try {
                function.setName(function.getName(), SourceType.USER_DEFINED); // Commit the function parameters
                HighFunction hf = res.getHighFunction();
                HighFunctionDBUtil.commitLocalNamesToDatabase(hf, SourceType.ANALYSIS);
                HighFunctionDBUtil.commitParamsToDatabase(hf, true, null, SourceType.ANALYSIS);
            } catch (Exception e) {
                Msg.error(ToolCalling.class, "Error committing local names: " + e.getMessage());
            }
        }
        
        ifc.closeProgram();
    }

}
