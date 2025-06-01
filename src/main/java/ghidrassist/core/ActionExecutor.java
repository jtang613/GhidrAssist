package ghidrassist.core;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class ActionExecutor {

    private static final Gson gson = new Gson();

    /**
     * Execute a specific action with the given arguments.
     * @param action The action to execute
     * @param argumentsJson JSON string containing action arguments
     * @param program The current program
     * @param address The current address
     * @throws Exception if action execution fails
     */
    public static void executeAction(String action, String argumentsJson, Program program, Address address) 
            throws Exception {
        JsonObject arguments = gson.fromJson(argumentsJson, JsonObject.class);
        
        // Start transaction
        int transaction = program.startTransaction("Execute " + action);
        boolean success = false;
        
        try {
            switch (action) {
                case "rename_function":
                    executeFunctionRename(arguments, program, address);
                    break;
                case "rename_variable":
                    executeVariableRename(arguments, program, address);
                    break;
                case "retype_variable":
                    executeVariableRetype(arguments, program, address);
                    break;
                case "auto_create_struct":
                    executeAutoCreateStruct(arguments, program, address);
                    break;
                default:
                    throw new InvalidInputException("Unknown action: " + action);
            }
            success = true;
        } finally {
            program.endTransaction(transaction, success);
        }
    }

    private static void executeFunctionRename(JsonObject arguments, Program program, Address address) 
            throws InvalidInputException, DuplicateNameException {
        String newName = arguments.get("new_name").getAsString().strip();
        Function function = getFunctionAtAddress(program, address);
        
        function.setName(newName, SourceType.USER_DEFINED);
    }

    private static void executeVariableRename(JsonObject arguments, Program program, Address address) 
            throws InvalidInputException, DuplicateNameException {
        String varName = arguments.get("var_name").getAsString().strip();
        String newName = arguments.get("new_name").getAsString().strip();
        
        Function function = getFunctionAtAddress(program, address);
        Variable variable = findVariable(function, varName);
        
        variable.setName(newName, SourceType.USER_DEFINED);
    }

    private static void executeVariableRetype(JsonObject arguments, Program program, Address address) 
            throws Exception {
        String varName = arguments.get("var_name").getAsString().strip();
        String newTypeStr = arguments.get("new_type").getAsString().strip();
        
        Function function = getFunctionAtAddress(program, address);
        Variable variable = findVariable(function, varName);
        
        DataType newType = parseDataType(newTypeStr, program.getDataTypeManager(), program);
        if (newType == null) {
            throw new InvalidInputException("Failed to parse data type: " + newTypeStr);
        }
        
        variable.setDataType(newType, true, true, SourceType.USER_DEFINED);
    }

    private static void executeAutoCreateStruct(JsonObject arguments, Program program, Address address) 
            throws Exception {
        String varName = arguments.get("var_name").getAsString().strip();
        Function function = getFunctionAtAddress(program, address);
        
        DecompInterface decompiler = new DecompInterface();
        try {
            setupDecompiler(decompiler, program);
            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            
            if (!results.decompileCompleted()) {
                throw new Exception("Decompilation failed for function: " + function.getName());
            }

            HighFunction highFunction = results.getHighFunction();
            HighVariable highVar = findHighVariable(highFunction, varName);
            
            if (highVar == null) {
                throw new InvalidInputException("Variable not found: " + varName);
            }

            createAndApplyStructure(program, function, highVar, decompiler);
            
        } finally {
            decompiler.dispose();
        }
    }

    private static Function getFunctionAtAddress(Program program, Address address) 
            throws InvalidInputException {
        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            throw new InvalidInputException("No function at address: " + address);
        }
        return function;
    }

    private static Variable findVariable(Function function, String varName) 
            throws InvalidInputException {
        // Commit local names to ensure all variables are available
        commitLocalNames(function.getProgram(), function);
        
        // Search in all variables and parameters
        List<Variable> allVars = new ArrayList<>();
        allVars.addAll(Arrays.asList(function.getAllVariables()));
        allVars.addAll(Arrays.asList(function.getParameters()));
        
        for (Variable var : allVars) {
            if (var.getName().equals(varName)) {
                return var;
            }
        }
        
        throw new InvalidInputException("Variable not found: " + varName);
    }

    private static DataType parseDataType(String typeStr, DataTypeManager dtm, Program program) 
            throws InvalidInputException, CancelledException, InvalidDataTypeException {
        // Try direct lookup first
        DataType dataType = dtm.getDataType(new CategoryPath("/"), typeStr);
        
        // If not found, try parsing
        if (dataType == null) {
            DataTypeParser parser = new DataTypeParser(dtm, program.getDataTypeManager(), null, DataTypeParser.AllowedDataTypes.ALL);
            dataType = parser.parse(typeStr);
        }
        
        return dataType;
    }

    private static void setupDecompiler(DecompInterface decompiler, Program program) {
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(program);
        decompiler.setOptions(options);
        decompiler.openProgram(program);
    }

    private static HighVariable findHighVariable(HighFunction highFunction, String varName) {
        var symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol sym = symbols.next();
            if (sym.getName().equals(varName)) {
                return sym.getHighVariable();
            }
        }
        return null;
    }

    private static void createAndApplyStructure(Program program, Function function, 
            HighVariable highVar, DecompInterface decompiler) throws Exception {
        
        FillOutStructureHelper fillHelper = new FillOutStructureHelper(program, TaskMonitor.DUMMY);
        Structure structDT = fillHelper.processStructure(highVar, function, false, true, decompiler);
        
        if (structDT == null) {
            throw new Exception("Failed to create structure");
        }

        // Add structure to data type manager
        DataTypeManager dtm = program.getDataTypeManager();
        structDT = (Structure) dtm.addDataType(structDT, DataTypeConflictHandler.DEFAULT_HANDLER);
        PointerDataType ptrStruct = new PointerDataType(structDT);

        // First get variable from function
        Variable var = findVariable(function, highVar.getSymbol().getName());
        
        if (var instanceof ghidra.program.model.listing.AutoParameterImpl) {
            // Modify the function signature to change the data type of the auto-parameter
            updateFunctionParameter(function, var.getName(), ptrStruct);
        } else {
            // Update local variable
            HighFunctionDBUtil.updateDBVariable(highVar.getSymbol(), null, ptrStruct, SourceType.USER_DEFINED);
        }
    }

    private static void updateFunctionParameter(Function function, String paramName, 
            DataType newType) throws InvalidInputException, DuplicateNameException {
        
        Parameter[] parameters = function.getParameters();
        Parameter[] newParams = new Parameter[parameters.length];

        for (int i = 0; i < parameters.length; i++) {
            if (parameters[i].getName().equals(paramName)) {
                newParams[i] = new ghidra.program.model.listing.ParameterImpl(
                    parameters[i].getName(),
                    newType,
                    parameters[i].getVariableStorage(),
                    function.getProgram(),
                    SourceType.USER_DEFINED
                );
            } else {
                newParams[i] = parameters[i];
            }
        }

        function.updateFunction(
            function.getCallingConventionName(),
            null, // Keep return type
            FunctionUpdateType.CUSTOM_STORAGE,
            true,
            SourceType.USER_DEFINED,
            newParams
        );
    }

    /**
     * Commits local variable names to the database for a function
     */
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
                Msg.error(ActionExecutor.class, "Error committing local names: " + e.getMessage());
            }
        }
        
        ifc.closeProgram();
    }
}