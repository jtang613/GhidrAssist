package ghidrassist.graphrag.extraction;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts security-relevant features from functions for reverse engineering.
 *
 * Detects:
 * - Network API calls (socket, send, recv, SSL, etc.)
 * - File I/O API calls (open, read, write, fopen, etc.)
 * - Crypto API calls (CryptEncrypt, AES, etc.)
 * - Process API calls (CreateProcess, exec, system, etc.)
 * - String references (IPs, URLs, file paths, domains, registry keys)
 */
public class SecurityFeatureExtractor {

    // ========================================
    // API Signature Sets
    // ========================================

    // Network APIs - POSIX, WinSock, WinSock2
    private static final Set<String> NETWORK_APIS = Set.of(
        // POSIX socket operations
        "socket", "bind", "listen", "accept", "connect", "close", "shutdown",
        "setsockopt", "getsockopt", "getpeername", "getsockname",
        // POSIX data transfer
        "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg",
        "read", "write",  // When used with sockets
        // POSIX multiplexing
        "select", "poll", "epoll_create", "epoll_ctl", "epoll_wait",
        "kqueue", "kevent",
        // WinSock / WinSock2 core
        "WSAStartup", "WSACleanup", "WSAGetLastError", "WSASetLastError",
        "closesocket",
        // WinSock2 socket creation
        "WSASocket", "WSASocketA", "WSASocketW",
        // WinSock2 connection
        "WSAConnect", "WSAConnectByName", "WSAConnectByNameA", "WSAConnectByNameW",
        "WSAConnectByList",
        // WinSock2 server (listen/accept)
        "WSAAccept",
        // WinSock2 data transfer
        "WSASend", "WSASendTo", "WSASendMsg", "WSASendDisconnect",
        "WSARecv", "WSARecvFrom", "WSARecvMsg", "WSARecvDisconnect",
        // WinSock2 async/event-based I/O
        "WSAAsyncSelect", "WSAEventSelect", "WSACreateEvent", "WSACloseEvent",
        "WSAWaitForMultipleEvents", "WSAEnumNetworkEvents", "WSAResetEvent", "WSASetEvent",
        // WinSock2 overlapped I/O
        "WSAIoctl", "WSAGetOverlappedResult",
        // WinSock2 address operations
        "WSAAddressToString", "WSAAddressToStringA", "WSAAddressToStringW",
        "WSAStringToAddress", "WSAStringToAddressA", "WSAStringToAddressW",
        // WinSock2 enumeration
        "WSAEnumProtocols", "WSAEnumProtocolsA", "WSAEnumProtocolsW",
        // DNS/resolution
        "getaddrinfo", "GetAddrInfo", "GetAddrInfoA", "GetAddrInfoW", "GetAddrInfoEx",
        "freeaddrinfo", "FreeAddrInfo", "FreeAddrInfoW",
        "gethostbyname", "gethostbyaddr", "gethostname",
        "getnameinfo", "GetNameInfo", "GetNameInfoW",
        "inet_addr", "inet_ntoa", "inet_pton", "inet_ntop",
        "InetPton", "InetPtonA", "InetPtonW", "InetNtop", "InetNtopA", "InetNtopW",
        "htons", "htonl", "ntohs", "ntohl",
        // SSL/TLS
        "SSL_connect", "SSL_accept", "SSL_read", "SSL_write", "SSL_new", "SSL_free",
        "SSL_CTX_new", "SSL_CTX_free", "SSL_set_fd", "SSL_shutdown",
        "SSL_library_init", "SSL_load_error_strings",
        "TLS_client_method", "TLS_server_method",
        // Windows Secure Channel (SChannel)
        "AcquireCredentialsHandle", "AcquireCredentialsHandleA", "AcquireCredentialsHandleW",
        "InitializeSecurityContext", "InitializeSecurityContextA", "InitializeSecurityContextW",
        "AcceptSecurityContext",
        "EncryptMessage", "DecryptMessage",
        // WinHTTP
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
        "WinHttpSendRequest", "WinHttpReceiveResponse",
        "WinHttpReadData", "WinHttpWriteData", "WinHttpQueryHeaders",
        "WinHttpCloseHandle", "WinHttpSetOption", "WinHttpQueryOption",
        "WinHttpCrackUrl", "WinHttpCreateUrl",
        // WinINet
        "InternetOpen", "InternetOpenA", "InternetOpenW",
        "InternetConnect", "InternetConnectA", "InternetConnectW",
        "InternetOpenUrl", "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetReadFile", "InternetReadFileEx",
        "InternetWriteFile",
        "InternetCloseHandle", "InternetSetOption", "InternetQueryOption",
        "HttpOpenRequest", "HttpOpenRequestA", "HttpOpenRequestW",
        "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
        "HttpSendRequestEx", "HttpSendRequestExA", "HttpSendRequestExW",
        "HttpQueryInfo", "HttpQueryInfoA", "HttpQueryInfoW",
        "HttpAddRequestHeaders", "HttpEndRequest",
        "FtpOpenFile", "FtpGetFile", "FtpPutFile", "FtpDeleteFile",
        "FtpCreateDirectory", "FtpRemoveDirectory", "FtpFindFirstFile",
        // libcurl
        "curl_easy_init", "curl_easy_perform", "curl_easy_cleanup",
        "curl_easy_setopt", "curl_easy_getinfo",
        "curl_multi_init", "curl_multi_add_handle", "curl_multi_perform"
    );

    // File I/O APIs - POSIX, C stdio, Win32
    private static final Set<String> FILE_IO_APIS = Set.of(
        // POSIX file operations
        "open", "close", "read", "write", "lseek", "pread", "pwrite",
        "creat", "dup", "dup2", "fcntl", "ioctl",
        "stat", "fstat", "lstat", "fstatat",
        "access", "faccessat", "chmod", "fchmod", "chown", "fchown",
        "truncate", "ftruncate",
        "mmap", "munmap", "msync",
        // C stdio
        "fopen", "fclose", "fread", "fwrite", "fgets", "fputs", "fgetc", "fputc",
        "fprintf", "fscanf", "fseek", "ftell", "fflush", "rewind", "feof", "ferror",
        "freopen", "fdopen", "fileno", "setvbuf", "setbuf",
        "getc", "putc", "ungetc", "getchar", "putchar",
        // POSIX directory operations
        "opendir", "closedir", "readdir", "readdir_r", "scandir", "seekdir", "telldir",
        "mkdir", "mkdirat", "rmdir", "chdir", "fchdir", "getcwd",
        // POSIX path operations
        "realpath", "basename", "dirname",
        "rename", "renameat", "remove", "unlink", "unlinkat",
        "link", "linkat", "symlink", "symlinkat", "readlink", "readlinkat",
        // Win32 file creation/opening
        "CreateFile", "CreateFileA", "CreateFileW",
        "CreateFile2",
        "OpenFile",
        // Win32 file read/write
        "ReadFile", "ReadFileEx", "ReadFileScatter",
        "WriteFile", "WriteFileEx", "WriteFileGather",
        "FlushFileBuffers",
        // Win32 file positioning
        "SetFilePointer", "SetFilePointerEx",
        "SetEndOfFile",
        // Win32 file info
        "GetFileSize", "GetFileSizeEx",
        "GetFileType",
        "GetFileTime", "SetFileTime",
        "GetFileInformationByHandle", "GetFileInformationByHandleEx",
        "SetFileInformationByHandle",
        // Win32 file attributes
        "GetFileAttributes", "GetFileAttributesA", "GetFileAttributesW",
        "GetFileAttributesEx", "GetFileAttributesExA", "GetFileAttributesExW",
        "SetFileAttributes", "SetFileAttributesA", "SetFileAttributesW",
        // Win32 file locking
        "LockFile", "LockFileEx", "UnlockFile", "UnlockFileEx",
        // Win32 file deletion/rename/copy/move
        "DeleteFile", "DeleteFileA", "DeleteFileW",
        "CopyFile", "CopyFileA", "CopyFileW",
        "CopyFileEx", "CopyFileExA", "CopyFileExW",
        "MoveFile", "MoveFileA", "MoveFileW",
        "MoveFileEx", "MoveFileExA", "MoveFileExW",
        "MoveFileWithProgress", "MoveFileWithProgressA", "MoveFileWithProgressW",
        "ReplaceFile", "ReplaceFileA", "ReplaceFileW",
        // Win32 file search/enumeration
        "FindFirstFile", "FindFirstFileA", "FindFirstFileW",
        "FindFirstFileEx", "FindFirstFileExA", "FindFirstFileExW",
        "FindNextFile", "FindNextFileA", "FindNextFileW",
        "FindClose",
        "SearchPath", "SearchPathA", "SearchPathW",
        // Win32 directory operations
        "CreateDirectory", "CreateDirectoryA", "CreateDirectoryW",
        "CreateDirectoryEx", "CreateDirectoryExA", "CreateDirectoryExW",
        "RemoveDirectory", "RemoveDirectoryA", "RemoveDirectoryW",
        "SetCurrentDirectory", "SetCurrentDirectoryA", "SetCurrentDirectoryW",
        "GetCurrentDirectory", "GetCurrentDirectoryA", "GetCurrentDirectoryW",
        // Win32 path operations
        "GetFullPathName", "GetFullPathNameA", "GetFullPathNameW",
        "GetLongPathName", "GetLongPathNameA", "GetLongPathNameW",
        "GetShortPathName", "GetShortPathNameA", "GetShortPathNameW",
        "GetTempPath", "GetTempPathA", "GetTempPathW",
        "GetTempFileName", "GetTempFileNameA", "GetTempFileNameW",
        "PathFileExists", "PathFileExistsA", "PathFileExistsW",
        // Win32 handle operations
        "CloseHandle", "DuplicateHandle",
        // Win32 memory-mapped files
        "CreateFileMapping", "CreateFileMappingA", "CreateFileMappingW",
        "OpenFileMapping", "OpenFileMappingA", "OpenFileMappingW",
        "MapViewOfFile", "MapViewOfFileEx", "UnmapViewOfFile",
        // Win32 async I/O
        "GetOverlappedResult", "GetOverlappedResultEx",
        "CancelIo", "CancelIoEx", "CancelSynchronousIo",
        // Win32 transacted file operations
        "CreateFileTransacted", "CreateFileTransactedA", "CreateFileTransactedW",
        "DeleteFileTransacted", "DeleteFileTransactedA", "DeleteFileTransactedW"
    );

    // Crypto APIs
    private static final Set<String> CRYPTO_APIS = Set.of(
        // Windows Crypto API
        "CryptAcquireContext", "CryptReleaseContext",
        "CryptGenKey", "CryptDeriveKey", "CryptDestroyKey",
        "CryptEncrypt", "CryptDecrypt",
        "CryptCreateHash", "CryptHashData", "CryptDestroyHash",
        "CryptSignHash", "CryptVerifySignature",
        "CryptImportKey", "CryptExportKey",
        // Windows CNG
        "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider",
        "BCryptGenerateKeyPair", "BCryptEncrypt", "BCryptDecrypt",
        "BCryptCreateHash", "BCryptHashData", "BCryptFinishHash",
        // OpenSSL
        "EVP_EncryptInit", "EVP_EncryptUpdate", "EVP_EncryptFinal",
        "EVP_DecryptInit", "EVP_DecryptUpdate", "EVP_DecryptFinal",
        "EVP_DigestInit", "EVP_DigestUpdate", "EVP_DigestFinal",
        "AES_encrypt", "AES_decrypt", "AES_set_encrypt_key", "AES_set_decrypt_key",
        "RSA_public_encrypt", "RSA_private_decrypt",
        "MD5_Init", "MD5_Update", "MD5_Final",
        "SHA1_Init", "SHA1_Update", "SHA1_Final",
        "SHA256_Init", "SHA256_Update", "SHA256_Final"
    );

    // Process/execution APIs
    private static final Set<String> PROCESS_APIS = Set.of(
        // POSIX
        "fork", "exec", "execl", "execle", "execlp", "execv", "execve", "execvp",
        "system", "popen", "pclose",
        "kill", "waitpid", "wait",
        // Windows
        "CreateProcess", "CreateProcessA", "CreateProcessW",
        "CreateProcessAsUser", "CreateProcessWithLogon",
        "ShellExecute", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteEx", "ShellExecuteExA", "ShellExecuteExW",
        "WinExec", "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
        "GetProcAddress", "FreeLibrary",
        "OpenProcess", "TerminateProcess",
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
        "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx"
    );

    // ========================================
    // Dangerous Functions - Vulnerability Indicators
    // ========================================

    /**
     * Map of dangerous function names to their vulnerability risk type.
     * These functions, when called, indicate potential security issues.
     */
    private static final Map<String, String> DANGEROUS_FUNCTIONS = Map.ofEntries(
        // Buffer overflow risks - unbounded string/memory operations
        Map.entry("strcpy", "BUFFER_OVERFLOW_RISK"),
        Map.entry("strcat", "BUFFER_OVERFLOW_RISK"),
        Map.entry("sprintf", "BUFFER_OVERFLOW_RISK"),
        Map.entry("vsprintf", "BUFFER_OVERFLOW_RISK"),
        Map.entry("gets", "BUFFER_OVERFLOW_RISK"),
        Map.entry("scanf", "BUFFER_OVERFLOW_RISK"),
        Map.entry("fscanf", "BUFFER_OVERFLOW_RISK"),
        Map.entry("sscanf", "BUFFER_OVERFLOW_RISK"),
        Map.entry("wcscpy", "BUFFER_OVERFLOW_RISK"),
        Map.entry("wcscat", "BUFFER_OVERFLOW_RISK"),
        Map.entry("lstrcpy", "BUFFER_OVERFLOW_RISK"),
        Map.entry("lstrcpyA", "BUFFER_OVERFLOW_RISK"),
        Map.entry("lstrcpyW", "BUFFER_OVERFLOW_RISK"),
        Map.entry("lstrcat", "BUFFER_OVERFLOW_RISK"),
        Map.entry("lstrcatA", "BUFFER_OVERFLOW_RISK"),
        Map.entry("lstrcatW", "BUFFER_OVERFLOW_RISK"),
        Map.entry("StrCpy", "BUFFER_OVERFLOW_RISK"),
        Map.entry("StrCat", "BUFFER_OVERFLOW_RISK"),
        Map.entry("_tcscpy", "BUFFER_OVERFLOW_RISK"),
        Map.entry("_tcscat", "BUFFER_OVERFLOW_RISK"),
        Map.entry("_mbscpy", "BUFFER_OVERFLOW_RISK"),
        Map.entry("_mbscat", "BUFFER_OVERFLOW_RISK"),

        // Format string risks
        Map.entry("printf", "FORMAT_STRING_RISK"),
        Map.entry("fprintf", "FORMAT_STRING_RISK"),
        Map.entry("wprintf", "FORMAT_STRING_RISK"),
        Map.entry("syslog", "FORMAT_STRING_RISK"),

        // Command injection risks
        Map.entry("system", "COMMAND_INJECTION_RISK"),
        Map.entry("popen", "COMMAND_INJECTION_RISK"),
        Map.entry("_popen", "COMMAND_INJECTION_RISK"),
        Map.entry("wpopen", "COMMAND_INJECTION_RISK"),
        Map.entry("execl", "COMMAND_INJECTION_RISK"),
        Map.entry("execle", "COMMAND_INJECTION_RISK"),
        Map.entry("execlp", "COMMAND_INJECTION_RISK"),
        Map.entry("execv", "COMMAND_INJECTION_RISK"),
        Map.entry("execve", "COMMAND_INJECTION_RISK"),
        Map.entry("execvp", "COMMAND_INJECTION_RISK"),
        Map.entry("WinExec", "COMMAND_INJECTION_RISK"),
        Map.entry("ShellExecute", "COMMAND_INJECTION_RISK"),
        Map.entry("ShellExecuteA", "COMMAND_INJECTION_RISK"),
        Map.entry("ShellExecuteW", "COMMAND_INJECTION_RISK"),
        Map.entry("ShellExecuteEx", "COMMAND_INJECTION_RISK"),
        Map.entry("ShellExecuteExA", "COMMAND_INJECTION_RISK"),
        Map.entry("ShellExecuteExW", "COMMAND_INJECTION_RISK"),

        // Integer overflow risks
        Map.entry("atoi", "INTEGER_OVERFLOW_RISK"),
        Map.entry("atol", "INTEGER_OVERFLOW_RISK"),
        Map.entry("atoll", "INTEGER_OVERFLOW_RISK"),
        Map.entry("strtol", "INTEGER_OVERFLOW_RISK"),
        Map.entry("strtoul", "INTEGER_OVERFLOW_RISK"),

        // Race condition risks
        Map.entry("access", "RACE_CONDITION_RISK"),
        Map.entry("stat", "RACE_CONDITION_RISK"),

        // Memory corruption risks
        Map.entry("alloca", "MEMORY_CORRUPTION_RISK"),
        Map.entry("_alloca", "MEMORY_CORRUPTION_RISK"),

        // Insecure random
        Map.entry("rand", "WEAK_RANDOM_RISK"),
        Map.entry("srand", "WEAK_RANDOM_RISK"),
        Map.entry("random", "WEAK_RANDOM_RISK"),

        // Deprecated/insecure crypto
        Map.entry("MD5_Init", "WEAK_CRYPTO_RISK"),
        Map.entry("MD5_Update", "WEAK_CRYPTO_RISK"),
        Map.entry("MD5_Final", "WEAK_CRYPTO_RISK"),
        Map.entry("MD5", "WEAK_CRYPTO_RISK"),
        Map.entry("SHA1_Init", "WEAK_CRYPTO_RISK"),
        Map.entry("SHA1_Update", "WEAK_CRYPTO_RISK"),
        Map.entry("SHA1_Final", "WEAK_CRYPTO_RISK"),
        Map.entry("DES_encrypt", "WEAK_CRYPTO_RISK"),
        Map.entry("DES_decrypt", "WEAK_CRYPTO_RISK")
    );

    // ========================================
    // String Pattern Matchers
    // ========================================

    // IP address pattern (IPv4)
    private static final Pattern IP_PATTERN = Pattern.compile(
        "^(\\d{1,3}\\.){3}\\d{1,3}$"
    );

    // URL pattern
    private static final Pattern URL_PATTERN = Pattern.compile(
        "^https?://[\\w.-]+(?:/[\\w./?%&=-]*)?$",
        Pattern.CASE_INSENSITIVE
    );

    // Unix file path pattern
    private static final Pattern UNIX_PATH_PATTERN = Pattern.compile(
        "^/[a-zA-Z0-9/_.-]+$"
    );

    // Windows file path pattern
    private static final Pattern WINDOWS_PATH_PATTERN = Pattern.compile(
        "^[A-Za-z]:\\\\[^<>:\"|?*]+$"
    );

    // Domain name pattern
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\\.[a-zA-Z]{2,}$"
    );

    // Windows registry key pattern
    private static final Pattern REGISTRY_PATTERN = Pattern.compile(
        "^(HKEY_|HK[A-Z]{2})[\\\\A-Za-z0-9_-]+$"
    );

    // Pattern to extract function calls from decompiled code
    private static final Pattern CALL_PATTERN = Pattern.compile(
        "\\b([A-Za-z_@][A-Za-z0-9_@!:.]*)\\s*\\("
    );

    // Keywords to exclude from call extraction (control flow, not function calls)
    private static final Set<String> CALL_KEYWORDS = Set.of(
        "if", "for", "while", "switch", "case", "return", "sizeof",
        "do", "catch", "try", "else", "new", "delete"
    );

    // ========================================
    // Instance fields
    // ========================================

    private final Program program;
    private final TaskMonitor monitor;

    /**
     * Create a SecurityFeatureExtractor.
     *
     * @param program The Ghidra program to analyze
     * @param monitor Task monitor for cancellation
     */
    public SecurityFeatureExtractor(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }

    // ========================================
    // Main Extraction Method
    // ========================================

    /**
     * Extract security features from a function.
     *
     * @param function The function to analyze
     * @return SecurityFeatures containing all detected features
     */
    public SecurityFeatures extractFeatures(Function function) {
        return extractFeatures(function, null);
    }

    /**
     * Extract security features from a function with optional decompiled code.
     * When decompiled code is provided, additional API calls are extracted via
     * regex parsing, catching calls that may not appear in the call graph.
     *
     * @param function The function to analyze
     * @param decompiledCode Optional decompiled C code for additional API extraction
     * @return SecurityFeatures containing all detected features
     */
    public SecurityFeatures extractFeatures(Function function, String decompiledCode) {
        SecurityFeatures features = new SecurityFeatures();

        if (function == null || program == null) {
            return features;
        }

        try {
            // 1. Detect API calls via called functions (from call graph)
            extractAPICalls(function, features);

            // 2. Extract API calls from decompiled code (catches more calls)
            if (decompiledCode != null && !decompiledCode.isEmpty()) {
                extractAPICallsFromCode(decompiledCode, features);
            }

            // 3. Extract string references
            extractStringReferences(function, features);

            // 4. Calculate activity profile and risk level
            features.calculateActivityProfile();
            features.calculateRiskLevel();

        } catch (Exception e) {
            Msg.warn(this, "Error extracting security features for " +
                function.getName() + ": " + e.getMessage());
        }

        return features;
    }

    // ========================================
    // API Call Detection
    // ========================================

    /**
     * Detect API calls by analyzing called functions.
     */
    private void extractAPICalls(Function function, SecurityFeatures features) {
        try {
            Set<Function> calledFunctions = function.getCalledFunctions(monitor);

            for (Function callee : calledFunctions) {
                if (monitor.isCancelled()) {
                    break;
                }

                String name = callee.getName();
                if (name == null || name.isEmpty()) {
                    continue;
                }

                // Normalize the function name to handle decorated names
                // Examples: _WSAGetLastError@0 -> WSAGetLastError, __imp_send -> send
                String normalizedName = normalizeFunctionName(name);

                // Check each API category using both original and normalized names
                if (NETWORK_APIS.contains(name) || NETWORK_APIS.contains(normalizedName)) {
                    features.addNetworkAPI(normalizedName);
                }
                if (FILE_IO_APIS.contains(name) || FILE_IO_APIS.contains(normalizedName)) {
                    features.addFileIOAPI(normalizedName);
                }
                if (CRYPTO_APIS.contains(name) || CRYPTO_APIS.contains(normalizedName)) {
                    features.addCryptoAPI(normalizedName);
                }
                if (PROCESS_APIS.contains(name) || PROCESS_APIS.contains(normalizedName)) {
                    features.addProcessAPI(normalizedName);
                }

                // Check for dangerous functions (vulnerability indicators)
                String vulnType = DANGEROUS_FUNCTIONS.get(name);
                if (vulnType == null) {
                    vulnType = DANGEROUS_FUNCTIONS.get(normalizedName);
                }
                if (vulnType != null) {
                    features.addDangerousFunction(normalizedName, vulnType);
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Error extracting API calls: " + e.getMessage());
        }
    }

    /**
     * Extract API calls from decompiled code using regex pattern matching.
     * This catches API calls that may not appear in the call graph, such as:
     * - Calls through function pointers
     * - Dynamically resolved imports
     * - Calls in inline code or macros
     *
     * @param decompiledCode The decompiled C code to analyze
     * @param features SecurityFeatures to update with detected APIs
     */
    private void extractAPICallsFromCode(String decompiledCode, SecurityFeatures features) {
        if (decompiledCode == null || decompiledCode.isEmpty()) {
            return;
        }

        Set<String> foundNames = new HashSet<>();
        Matcher matcher = CALL_PATTERN.matcher(decompiledCode);

        while (matcher.find()) {
            String candidate = matcher.group(1);
            if (candidate == null || candidate.isEmpty()) {
                continue;
            }

            // Skip control flow keywords
            if (CALL_KEYWORDS.contains(candidate.toLowerCase())) {
                continue;
            }

            foundNames.add(candidate);
        }

        // Check each found name against API sets
        for (String name : foundNames) {
            String normalizedName = normalizeFunctionName(name);

            // Check each API category
            if (NETWORK_APIS.contains(name) || NETWORK_APIS.contains(normalizedName)) {
                features.addNetworkAPI(normalizedName);
            }
            if (FILE_IO_APIS.contains(name) || FILE_IO_APIS.contains(normalizedName)) {
                features.addFileIOAPI(normalizedName);
            }
            if (CRYPTO_APIS.contains(name) || CRYPTO_APIS.contains(normalizedName)) {
                features.addCryptoAPI(normalizedName);
            }
            if (PROCESS_APIS.contains(name) || PROCESS_APIS.contains(normalizedName)) {
                features.addProcessAPI(normalizedName);
            }

            // Check for dangerous functions
            String vulnType = DANGEROUS_FUNCTIONS.get(name);
            if (vulnType == null) {
                vulnType = DANGEROUS_FUNCTIONS.get(normalizedName);
            }
            if (vulnType != null) {
                features.addDangerousFunction(normalizedName, vulnType);
            }
        }
    }

    /**
     * Normalize a function name by stripping common decorations:
     * - Leading underscores (_func, __func, __imp_func)
     * - Trailing @N suffix (stdcall decoration like @0, @4, @8)
     * - Trailing W or A suffix for Unicode/ANSI variants (if not in API set)
     */
    private String normalizeFunctionName(String name) {
        if (name == null || name.isEmpty()) {
            return name;
        }

        String normalized = name;

        // Strip __imp_ prefix (import thunk)
        if (normalized.startsWith("__imp_")) {
            normalized = normalized.substring(6);
        }

        // Strip leading underscores (but keep at least the core name)
        while (normalized.startsWith("_") && normalized.length() > 1) {
            normalized = normalized.substring(1);
        }

        // Strip trailing @N (stdcall decoration)
        int atIndex = normalized.lastIndexOf('@');
        if (atIndex > 0) {
            String suffix = normalized.substring(atIndex + 1);
            // Check if suffix is all digits
            if (suffix.matches("\\d+")) {
                normalized = normalized.substring(0, atIndex);
            }
        }

        return normalized;
    }

    // ========================================
    // String Reference Extraction
    // ========================================

    /**
     * Extract string references from the function body.
     */
    private void extractStringReferences(Function function, SecurityFeatures features) {
        ReferenceManager refMgr = program.getReferenceManager();
        AddressSetView body = function.getBody();

        try {
            // Iterate through all addresses in the function body
            for (Address addr : body.getAddresses(true)) {
                if (monitor.isCancelled()) {
                    break;
                }

                // Get references FROM this address
                Reference[] refs = refMgr.getReferencesFrom(addr);
                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();

                    // Try to get data at the referenced address
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null && data.hasStringValue()) {
                        Object value = data.getValue();
                        if (value != null) {
                            classifyString(value.toString(), features);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Error extracting string references: " + e.getMessage());
        }
    }

    /**
     * Classify a string and add to appropriate category.
     */
    private void classifyString(String value, SecurityFeatures features) {
        if (value == null || value.isEmpty() || value.length() < 3) {
            return;
        }

        // Clean up the string
        value = value.trim();

        // Check patterns in order of specificity
        if (IP_PATTERN.matcher(value).matches()) {
            // Validate IP octets are 0-255
            if (isValidIPAddress(value)) {
                features.addIPAddress(value);
            }
        } else if (URL_PATTERN.matcher(value).matches()) {
            features.addURL(value);
        } else if (REGISTRY_PATTERN.matcher(value).matches()) {
            features.addRegistryKey(value);
        } else if (UNIX_PATH_PATTERN.matcher(value).matches()) {
            features.addFilePath(value);
        } else if (WINDOWS_PATH_PATTERN.matcher(value).matches()) {
            features.addFilePath(value);
        } else if (DOMAIN_PATTERN.matcher(value).matches()) {
            // Avoid false positives from common patterns
            if (!isCommonNonDomain(value)) {
                features.addDomain(value);
            }
        }
    }

    /**
     * Validate IP address octets are in valid range.
     */
    private boolean isValidIPAddress(String ip) {
        try {
            String[] parts = ip.split("\\.");
            if (parts.length != 4) {
                return false;
            }
            for (String part : parts) {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) {
                    return false;
                }
            }
            // Exclude common non-network IPs
            if (ip.equals("0.0.0.0") || ip.equals("255.255.255.255")) {
                return true;  // Include special IPs
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Check if a string looks like a domain but is probably not.
     */
    private boolean isCommonNonDomain(String value) {
        // Common false positives
        String lower = value.toLowerCase();
        return lower.endsWith(".dll") ||
               lower.endsWith(".exe") ||
               lower.endsWith(".sys") ||
               lower.endsWith(".lib") ||
               lower.endsWith(".obj") ||
               lower.endsWith(".pdb") ||
               lower.endsWith(".h") ||
               lower.endsWith(".c") ||
               lower.endsWith(".cpp") ||
               lower.equals("version.rc") ||
               lower.contains("microsoft.com") && lower.contains("schema");
    }

    // ========================================
    // Static Analysis Helpers
    // ========================================

    /**
     * Check if a function name suggests network activity.
     */
    public static boolean suggestsNetworkActivity(String functionName) {
        if (functionName == null) return false;
        String lower = functionName.toLowerCase();
        return lower.contains("socket") ||
               lower.contains("connect") ||
               lower.contains("send") ||
               lower.contains("recv") ||
               lower.contains("http") ||
               lower.contains("download") ||
               lower.contains("upload") ||
               lower.contains("network") ||
               lower.contains("client") ||
               lower.contains("server");
    }

    /**
     * Check if a function name suggests file activity.
     */
    public static boolean suggestsFileActivity(String functionName) {
        if (functionName == null) return false;
        String lower = functionName.toLowerCase();
        return lower.contains("file") ||
               lower.contains("read") ||
               lower.contains("write") ||
               lower.contains("open") ||
               lower.contains("save") ||
               lower.contains("load") ||
               lower.contains("config") ||
               lower.contains("log");
    }

    /**
     * Check if a function name suggests crypto activity.
     */
    public static boolean suggestsCryptoActivity(String functionName) {
        if (functionName == null) return false;
        String lower = functionName.toLowerCase();
        return lower.contains("crypt") ||
               lower.contains("encrypt") ||
               lower.contains("decrypt") ||
               lower.contains("hash") ||
               lower.contains("aes") ||
               lower.contains("rsa") ||
               lower.contains("sha") ||
               lower.contains("md5");
    }
}
