package com.acquia.http;

import java.io.IOException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;

/**
 * An HttpRequestInterceptor that adds the Authorization header that contains the HMAC.
 * 
 * @author chris.nagy
 *
 */
public class HMACHttpRequestInterceptor implements HttpRequestInterceptor {

    /**
     * The Authorization provider
     */
    protected String provider;
    /**
     * The access key
     */
    protected String accessKey;
    /**
     * The secret key
     */
    protected String secretKey;
    
    /**
     * The list of custom header names to use when creating the message to be encrypted
     */
    protected List<String> customHeaders;
    
    /**
     * The algorithm to use when creating the HMAC
     */
    protected HMACAlgorithm algorithm;
    
    /**
     * Create an HMACHttpRequestInterceptor with the given provider, access key and secret key. Use
     * the algorithm with the given name to create the HMAC.
     * 
     * @param provider Authorization provider
     * @param accessKey Access Key
     * @param secretKey Secret Key
     * @param algorithmName Name of Algorithm
     */
    public HMACHttpRequestInterceptor( String provider, String accessKey, String secretKey, String algorithmName) {
        this.provider = provider;
        this.accessKey = accessKey;
        this.secretKey = secretKey;

        HMACAlgorithmFactory algorithmFactory = new HMACAlgorithmFactory();
        this.algorithm = algorithmFactory.createAlgorithm(algorithmName);

        this.customHeaders = new ArrayList<String>();
    }
    
    /**
     * Sets the custom HTTP header names to use when constructing the message.
     * 
     * @param customHeaders The list of HTTP header names
     */
    public void setCustomHeaders( String[] customHeaders ) {
        this.customHeaders = new ArrayList<String>( Arrays.asList( customHeaders ) ) ;
    }
    
    /** 
     * Returns the custom header names to use when constructing the message.
     * 
     * @return The list of HTTP header names
     */
    public String[] getCustomHeaders() {
        return this.customHeaders.toArray(new String[ this.customHeaders.size() ]);
    }
    
    @Override
    public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
        HMACMessageCreator messageCreator = new HMACMessageCreator();
        String message = messageCreator.createMessage( request, this.customHeaders );
        System.out.println("===start message===");
        System.out.println(message);
        System.out.println("===end message===");
        try {
            String encryptedMessage = this.algorithm.encryptMessage( this.secretKey, message);
            StringBuilder authHeader = new StringBuilder( this.provider );
            authHeader.append(" ");
            authHeader.append(this.accessKey);
            authHeader.append(":");
            authHeader.append(encryptedMessage);
            request.addHeader("Authorization", authHeader.toString());
        }
        catch ( SignatureException e ) {
            throw new IOException("Could not encrypt message", e);
        }
    }



}
