package com.ainge.easycrypto.generators;

import java.security.SecureRandom;

/**
 * @author: Ainge
 * @Time: 2019/12/20 23:44
 */
public class SecureRandomGenerator {

    /**
     * 生成强随机数（性能稍慢）
     * (默认使用sun提供的spi， 在linux下默认-Djava.security.egd=file:/dev/random 获取，会阻塞)
     * 如果遇到性能问题，可以添加启动参数改为伪随机（启动参数添加 -Djava.security.egd=file:/dev/./urandom）
     *
     * @param length
     * @return
     */
    public static byte[] randomBytes(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return randomBytes(length, null);
    }

    public static byte[] randomBytes(int length, SecureRandom secureRandom) {
        secureRandom = (secureRandom == null) ? new SecureRandom() : secureRandom;
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }


}
