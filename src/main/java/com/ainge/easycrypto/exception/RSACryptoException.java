package com.ainge.easycrypto.exception;

/**
 * @author: Ainge
 */
public class RSACryptoException extends CryptoException {

    public RSACryptoException() {
        super();
    }

    public RSACryptoException(String message) {
        super(message);
    }

    public RSACryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public RSACryptoException(Throwable cause) {
        super(cause);
    }

    protected RSACryptoException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
