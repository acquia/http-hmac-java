package com.acquia.http;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.protocol.HttpContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An HttpResponseInterceptor that adds X-Server-Authorization-HMAC-SHA256 response header that contains the encrypted response
 * 
 * @author aric.tatan
 *
 */
public class HMACHttpResponseInterceptor implements HttpResponseInterceptor {

    private static Logger logger = LogManager.getLogger(HttpResponseInterceptor.class);

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
     * @param secretKey; secret key used to encrypt the message
     * @param algorithmName; for example: SHA256
     */
    public HMACHttpResponseInterceptor(String secretKey, String algorithmName) {
        this.secretKey = secretKey;

        HMACAlgorithmFactory algorithmFactory = new HMACAlgorithmFactory();
        this.algorithm = algorithmFactory.createAlgorithm(algorithmName);
    }

    @Override
    public void process(HttpResponse response, HttpContext context)
            throws HttpException, IOException {
        //get httpVerb
        String httpVerb = (String) context.getAttribute(
            HMACHttpRequestInterceptor.CONTEXT_HTTP_VERB);
        if (httpVerb == null) {
            String message = "Error: No httpVerb in the HTTP context.";
            logger.error(message);
            throw new HttpException(message);
        }

        //upon HEAD method, server will not append server validation header
        if (!httpVerb.equals("HEAD")) {
            //get server response signature
            Header serverAuthResponseHeader = response.getFirstHeader(
                HMACMessageCreator.PARAMETER_X_SERVER_AUTHORIZATION_HMAC_SHA256);
            if (serverAuthResponseHeader == null) {
                StringBuffer statusBuffer = new StringBuffer("Error: Server failed to provide "
                        + HMACMessageCreator.PARAMETER_X_SERVER_AUTHORIZATION_HMAC_SHA256
                        + ", response validation header.");
                statusBuffer.append("\n---- Interceptor Signable Request Message:\n").append(
                    (String) context.getAttribute(
                        HMACHttpRequestInterceptor.CONTEXT_SIGNABLE_REQUEST_MESSAGE));
                statusBuffer.append("\n---- Interceptor Signed Request Message:\n").append(
                    (String) context.getAttribute(
                        HMACHttpRequestInterceptor.CONTEXT_SIGNED_REQUEST_MESSAGE));
                statusBuffer.append("\n---- Server Response Status Line:\n").append(
                    response.getStatusLine().toString());

                String message = statusBuffer.toString();
                logger.error(message);
                throw new HttpException(message);
            }
            String serverSignature = serverAuthResponseHeader.getValue();

            //get nonce of when request was made
            HMACAuthorizationHeader authHeader = (HMACAuthorizationHeader) context.getAttribute(
                HMACHttpRequestInterceptor.CONTEXT_AUTH_HEADER);
            if (authHeader == null) {
                String message = "Error: No authHeader in the HTTP context.";
                logger.error(message);
                throw new HttpException(message);
            }
            String nonce = authHeader.getNonce();

            //get xAuthorizationTimestamp of when request was made
            String xAuthorizationTimestamp = (String) context.getAttribute(
                HMACHttpRequestInterceptor.CONTEXT_X_AUTHORIZATION_TIMESTAMP);
            if (xAuthorizationTimestamp == null) {
                String message = "Error: No xAuthorizationTimestamp in the HTTP context.";
                logger.error(message);
                throw new HttpException(message);
            }

            //get server response body
            String responseContent = "";
            final HttpEntity entity = response.getEntity();
            if (entity != null && entity.getContentLength() > 0) {
                //response body can only be consumed once - so copy this somewhere
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                entity.writeTo(baos);
                baos.flush();
                baos.close();
                responseContent = baos.toString(HMACMessageCreator.ENCODING_UTF_8);

                //set the entity again so it is ready for further consumption
                response.setEntity(new HttpEntity() {
                    @Override
                    public boolean isRepeatable() {
                        return entity.isRepeatable();
                    }

                    @Override
                    public boolean isChunked() {
                        return entity.isChunked();
                    }

                    @Override
                    public long getContentLength() {
                        return entity.getContentLength();
                    }

                    @Override
                    public Header getContentType() {
                        return entity.getContentType();
                    }

                    @Override
                    public Header getContentEncoding() {
                        return entity.getContentEncoding();
                    }

                    @Override
                    public InputStream getContent() throws IOException, IllegalStateException {
                        return new ByteArrayInputStream(baos.toByteArray());
                    }

                    @Override
                    public void writeTo(OutputStream outstream) throws IOException {
                        entity.writeTo(outstream);
                    }

                    @Override
                    public boolean isStreaming() {
                        return entity.isStreaming();
                    }

                    @SuppressWarnings("deprecation")
                    @Override
                    public void consumeContent() throws IOException {
                        entity.consumeContent();
                    }
                });
            }

            //check response validity
            HMACMessageCreator messageCreator = new HMACMessageCreator();
            String signableResponseMessage = messageCreator.createSignableResponseMessage(nonce,
                xAuthorizationTimestamp, responseContent);
            logger.trace("signableResponseMessage:\n" + signableResponseMessage);
            String signedResponseMessage = "";
            try {
                signedResponseMessage = this.algorithm.encryptMessage(this.secretKey,
                    signableResponseMessage);
                logger.trace("signedResponseMessage:\n" + signedResponseMessage);
            } catch(SignatureException e) {
                String message = "Fail to sign response message";
                logger.error(message);
                throw new IOException(message, e);
            }

            if (serverSignature.compareTo(signedResponseMessage) != 0) {
                String message = "Error: Invalid server response validation.";
                logger.error(message);
                throw new HttpException(message);
            }
        }
    }

}
