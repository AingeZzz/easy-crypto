package com.ainge.easycrypto.exception;

/**
 * @author: Ainge
 */
public class AESCryptoException extends CryptoException{
    public AESCryptoException() {
        super();
    }

    public AESCryptoException(String message) {
        super(message);
    }

    public AESCryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public AESCryptoException(Throwable cause) {
        super(cause);
    }

    protected AESCryptoException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
