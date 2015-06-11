package com.acquia.http;

import java.security.SignatureException;

/**
 * The HMACAlgorithm interface defines a method to encrypt the message based on the secret key.
 * 
 * @author chris.nagy
 *
 */
public interface HMACAlgorithm {
    
    /**
     * Encrypt the given message using the given secret key.
     * 
     * @param secretKey Secret Key
     * @param message Message
     * @return One-way encrypted message
     * @throws SignatureException If there is an error or the system doesn't support the encryption method
     */
    String encryptMessage( String secretKey, String message ) throws SignatureException;
}
