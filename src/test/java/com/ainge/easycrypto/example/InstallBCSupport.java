package com.ainge.easycrypto.example;

import com.ainge.easycrypto.BouncyCastleProviderSupport;

/**
 * @author: Ainge
 * @Time: 2019/12/21 22:28
 */
public class InstallBCSupport {
    static {
        // 整个JVM中只需要执行一次就可以了
        BouncyCastleProviderSupport.support();
    }
}
