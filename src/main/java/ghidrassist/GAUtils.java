package ghidrassist;

import java.io.File;

public class GAUtils {
	public enum OperatingSystem {
	    WINDOWS, MAC, LINUX, UNKNOWN;
	
	    public static OperatingSystem detect() {
	        String os = System.getProperty("os.name").toLowerCase();
	        if (os.contains("win")) {
	            return WINDOWS;
	        } else if (os.contains("mac")) {
	            return MAC;
	        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
	            return LINUX;
	        } else {
	            return UNKNOWN;
	        }
	    }
	}
	
	public static String getDefaultLucenePath(OperatingSystem os) {
	    String basePath;
	    switch (os) {
	        case WINDOWS:
	            basePath = System.getenv("LOCALAPPDATA");
	            if (basePath == null) {
	                throw new RuntimeException("Unable to access LOCALAPPDATA environment variable.");
	            }
	            break;

	        case MAC:
	            basePath = System.getProperty("user.home") + "/Library/Application Support";
	            break;

	        case LINUX:
	            basePath = System.getProperty("user.home") + "/.config";
	            break;

	        default:
	            throw new UnsupportedOperationException("Unsupported operating system: " + os);
	    }
	    return basePath + File.separator + "GhidrAssist" + File.separator + "LuceneIndex";
	}

}