package com.ainge.easycrypto.jose.jwe;

/**
 * Created by Ainge on 2019/11/24
 */
public class CompactSerializer {
    private static final String PERIOD_SEPARATOR = ".";
    private static final String PERIOD_SEPARATOR_REGEX = "\\.";

    private static final String EMPTY_STRING = "";

    public static String[] deserialize(String compactSerialization) {
        if (compactSerialization == null || "".equals(compactSerialization.trim())) {
            throw new IllegalArgumentException();
        }
        String[] parts = compactSerialization.split(PERIOD_SEPARATOR_REGEX);

        if (compactSerialization.endsWith(PERIOD_SEPARATOR)) {
            String[] tempParts = new String[parts.length + 1];
            System.arraycopy(parts, 0, tempParts, 0, parts.length);
            tempParts[parts.length] = EMPTY_STRING;
            parts = tempParts;
        }

        return parts;
    }

    public static String serialize(String... parts) {
        if (parts == null) {
            throw new IllegalArgumentException();
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            String part = (parts[i] == null) ? EMPTY_STRING : parts[i];
            sb.append(part);
            if (i != parts.length - 1) {
                sb.append(PERIOD_SEPARATOR);
            }
        }
        return sb.toString();
    }

}
