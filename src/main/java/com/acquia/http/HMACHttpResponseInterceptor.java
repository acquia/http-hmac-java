package com.acquia.http;

import java.io.IOException;
import java.security.SignatureException;

import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.protocol.HttpContext;

/**
 * An HttpResponseInterceptor that adds X-Server-Authorization-HMAC-SHA256 response header that contains the encrypted response
 * 
 * @author aric.tatan
 *
 */
public class HMACHttpResponseInterceptor implements HttpResponseInterceptor {

    /**
     * Timestamp when request was made
     */
    protected String xAuthorizationTimestamp;

    /**
     * Nonce when request was made
     */
    protected String nonce;

    /**
     * Response body
     */
    protected String responseBody;

    /**
     * The secret key
     */
    protected String secretKey;

    /**
     * The algorithm to use when creating the HMAC
     */
    protected HMACAlgorithm algorithm;

    /**
     * Constructor
     * 
     * @param nonce; nonce when request was made
     * @param xAuthorizationTimestamp; timestamp when request was made
     * @param responseBody; response body
     * @param secretKey; secret key used to encrypt the message
     * @param algorithmName; for example: SHA256
     */
    public HMACHttpResponseInterceptor(String nonce, String xAuthorizationTimestamp,
            String responseBody, String secretKey, String algorithmName) {
        this.nonce = nonce;
        this.xAuthorizationTimestamp = xAuthorizationTimestamp;
        if (responseBody == null) {
            this.responseBody = "";
        } else {
            this.responseBody = responseBody;
        }
        this.secretKey = secretKey;

        HMACAlgorithmFactory algorithmFactory = new HMACAlgorithmFactory();
        this.algorithm = algorithmFactory.createAlgorithm(algorithmName);
    }

    @Override
    public void process(HttpResponse response, HttpContext context) throws HttpException,
            IOException {
        String signableResponseMessage = this.createMessage();
        System.out.println("---- message:\n" + signableResponseMessage);
        String signedResponseMessage = "";
        try {
            signedResponseMessage = this.algorithm.encryptMessage(this.secretKey,
                signableResponseMessage);
        } catch(SignatureException e) {
            throw new IOException("Fail to sign response message", e);
        }
        System.out.println("---- encryptedMessage:\n" + signedResponseMessage);

        response.setHeader("X-Server-Authorization-HMAC-SHA256", signedResponseMessage);
    }

    /**
     * Helper method to create response signature message
     * 
     * @return
     */
    private String createMessage() {
        StringBuilder responseSignatureBuilder = new StringBuilder();
        responseSignatureBuilder.append(this.nonce).append("\n");
        responseSignatureBuilder.append(this.xAuthorizationTimestamp).append("\n");
        responseSignatureBuilder.append(this.responseBody);
        return responseSignatureBuilder.toString();
    }

}
