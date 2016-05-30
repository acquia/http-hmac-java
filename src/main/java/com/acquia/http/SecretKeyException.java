package com.acquia.http;

/**
 * Exception that is thrown when trying to get secret/private key given access/public key.
 * 
 * @author aric.tatan
 *
 */
public class SecretKeyException extends Exception {

    private static final long serialVersionUID = -8918809922281463624L;

    public static final String NOT_FOUND = "No secret key is associated with the given access key.";
    public static final String CANNOT_RETRIEVE = "Fail to obtain secret/private key from the authorization server.";

    public SecretKeyException(String message) {
        super(message);
    }

}
