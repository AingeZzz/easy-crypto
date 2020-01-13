package com.ainge.easycrypto.util;

/**
 * @author: Ainge
 * @Time: 2020/1/14 01:04
 */
public class StringUtils {

    public static String defaultString(final String str) {
        return defaultString(str, "");
    }

    public static String defaultString(final String str, final String defaultStr) {
        return str == null ? defaultStr : str;
    }
}
