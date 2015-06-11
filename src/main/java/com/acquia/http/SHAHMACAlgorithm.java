package com.acquia.http;

import java.security.SignatureException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * The SHAHMACAlgorithm class creates HMACs by using the SHA algorithm. Supports 1, 256, 384 and 512 sizes.
 * 
 * @author chris.nagy
 *
 */
public class SHAHMACAlgorithm implements HMACAlgorithm {

    /**
     * The name of the algorithm. See Java Cryptography Architecture Reference Guide for valid names.
     */
    String algorithm = null;
    
    /**
     * Constructs a new SHAHMACAlgorithm with the given size.
     * 
     * @param shaSize key size
     */
    protected SHAHMACAlgorithm( int shaSize ) {
        if ( shaSize != 1 && shaSize != 256 && shaSize != 384 && shaSize != 512 ) {
            throw new IllegalArgumentException("Size "+shaSize+" not supported (only 1, 256, 384 and 512 are supported)");
        }
        algorithm = "HmacSHA"+Integer.toString(shaSize);
    }
    
    @Override
    public String encryptMessage(String secretKey, String message) throws SignatureException {
        String result;
        try {
            SecretKeySpec signingKey = new SecretKeySpec(secretKey.getBytes(), algorithm);

            Mac mac = Mac.getInstance(algorithm);
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(message.getBytes());

            result = Base64.encodeBase64String(rawHmac);

        } catch(Exception e) {
            throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
        }
        return result;
    }

}
