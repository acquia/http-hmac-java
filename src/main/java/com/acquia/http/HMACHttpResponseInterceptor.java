package com.acquia.http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.SignatureException;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
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
            String secretKey, String algorithmName) {
        this.nonce = nonce;
        this.xAuthorizationTimestamp = xAuthorizationTimestamp;
        this.secretKey = secretKey;

        HMACAlgorithmFactory algorithmFactory = new HMACAlgorithmFactory();
        this.algorithm = algorithmFactory.createAlgorithm(algorithmName);
    }

    @Override
    public void process(HttpResponse response, HttpContext context) throws HttpException,
            IOException {
        //get server response signature
        String serverSignature = "";
        Header serverAuthResponseHeader = response.getFirstHeader(HMACMessageCreator.PARAMETER_X_SERVER_AUTHORIZATION_HMAC_SHA256);
        if (serverAuthResponseHeader != null) {
            serverSignature = serverAuthResponseHeader.getValue();
        }

        //get server response body
        String responseBody = "";
        HttpEntity entity = response.getEntity();
        if (entity != null && entity.getContentLength() > 0) {
            StringBuilder respStringBuilder = new StringBuilder();
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(
                    entity.getContent()), 1000);
                String line = null;
                while ((line = reader.readLine()) != null) {
                    respStringBuilder.append(line);
                }
            } catch(IOException e) {
                e.printStackTrace();
            } catch(Exception e) {
                e.printStackTrace();
            }
            responseBody = respStringBuilder.toString();
        }

        //check response validity
        String signableResponseMessage = this.createMessage(responseBody);
        String signedResponseMessage = "";
        try {
            signedResponseMessage = this.algorithm.encryptMessage(this.secretKey,
                signableResponseMessage);
        } catch(SignatureException e) {
            throw new IOException("Fail to sign response message", e);
        }

        if (serverSignature.compareTo(signedResponseMessage) != 0) {
            throw new HttpException("Error: Invalid server response validation."); //FIXME: is throwing HttpException okay?
        }
    }

    /**
     * Helper method to create response signature message
     * 
     * @return
     */
    private String createMessage(String responseBody) {
        StringBuilder responseSignatureBuilder = new StringBuilder();
        responseSignatureBuilder.append(this.nonce).append("\n");
        responseSignatureBuilder.append(this.xAuthorizationTimestamp).append("\n");
        responseSignatureBuilder.append(responseBody);
        return responseSignatureBuilder.toString();
    }

}
