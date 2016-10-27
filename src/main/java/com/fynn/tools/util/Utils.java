package com.fynn.tools.util;

public class Utils {
	
	public static int stringToInt(String value) {
		if (value == null || value.trim().equals("")) {
			return 0;
		} else {
			return new Integer(value);
		}
	}
	
	public static boolean nullOrBlank(String str){
		return str == null || "".equals(str);
	}

}
