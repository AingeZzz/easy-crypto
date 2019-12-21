package com.ainge.easycrypto.util;

import com.ainge.easycrypto.exception.UncheckedException;
import com.ainge.easycrypto.generators.SecureRandomGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * @author: Ainge
 * @Time: 2019/12/21 14:03
 */
public class ByteUtil {

    public static final byte[] EMPTY_BYTES = new byte[0];

    private static final int MAX_BYTE_LENGTH = Integer.MAX_VALUE / 8;


    /**
     * 将int值转为byte数组
     *
     * @param intValue
     * @return
     */
    public static byte[] getBytes(int intValue) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.putInt(intValue);
        return byteBuffer.array();
    }

    /**
     * 将long值转为byte数组
     *
     * @param longValue
     * @return
     */
    public static byte[] getBytes(long longValue) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(8);
        byteBuffer.putLong(longValue);
        return byteBuffer.array();
    }

    /**
     * 将byte值转为int
     *
     * @param b
     * @return
     */
    public static int getInt(byte b) {
        return (b >= 0) ? (int) b : 256 - (~(b - 1));
    }

    /**
     * 比较两byte数组是否相等
     *
     * @param bytes1
     * @param bytes2
     * @return
     */
    public static boolean secureEquals(byte[] bytes1, byte[] bytes2) {
        bytes1 = (bytes1 == null) ? EMPTY_BYTES : bytes1;
        bytes2 = (bytes2 == null) ? EMPTY_BYTES : bytes2;

        int shortest = Math.min(bytes1.length, bytes2.length);
        int longest = Math.max(bytes1.length, bytes2.length);

        int result = 0;

        for (int i = 0; i < shortest; i++) {
            result |= bytes1[i] ^ bytes2[i];
        }

        return (result == 0) && (shortest == longest);
    }

    /**
     * 合并数组
     *
     * @param byteArrays
     * @return
     */
    public static byte[] concat(byte[]... byteArrays) {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            for (byte[] bytes : byteArrays) {
                byteArrayOutputStream.write(bytes);
            }
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("IOEx from ByteArrayOutputStream?!", e);
        }
    }

    /**
     * 数组截取
     *
     * @param inputBytes
     * @param startPos
     * @param length
     * @return
     */
    public static byte[] subArray(byte[] inputBytes, int startPos, int length) {
        byte[] subArray = new byte[length];
        System.arraycopy(inputBytes, startPos, subArray, 0, subArray.length);
        return subArray;
    }

    /**
     * 获取数组的左边部分
     * @param inputBytes
     * @return
     */
    public static byte[] leftHalf(byte[] inputBytes) {
        return subArray(inputBytes, 0, (inputBytes.length / 2));
    }

    /**
     * 获取数组的右边部分
     * @param inputBytes
     * @return
     */
    public static byte[] rightHalf(byte[] inputBytes) {
        int half = inputBytes.length / 2;
        return subArray(inputBytes, half, half);
    }

    /**
     * 获取byte数组的bits长度（1字节有8位）
     * @param bytes
     * @return
     */
    public static int bitLength(byte[] bytes) {
        return bitLength(bytes.length);
    }

    /**
     * 将byte长度转为bit长度（1字节有8位）
     * @param byteLength
     * @return
     */
    public static int bitLength(int byteLength) {
        if (byteLength > MAX_BYTE_LENGTH || (byteLength < 0)) {
            throw new UncheckedException("Invalid byte length (" + byteLength + ") for converting to bit length");
        }
        return byteLength * 8;
    }

    /**
     * 将bit长度转为byte长度(1字节=8位)
     * @param numberOfBits
     * @return
     */
    public static int byteLength(int numberOfBits) {
        return numberOfBits / 8;
    }

    /**
     * 产生强随机数，
     *
     * @param length
     * @return
     */
    public static byte[] randomBytes(int length) {
        return SecureRandomGenerator.randomBytes(length);
    }

}
