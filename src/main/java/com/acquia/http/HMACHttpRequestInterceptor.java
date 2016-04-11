package com.acquia.http;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
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

    public static final String CONTEXT_HTTP_VERB = "httpVerb";
    public static final String CONTEXT_AUTH_HEADER = "authHeader";
    public static final String CONTEXT_X_AUTHORIZATION_TIMESTAMP = "xAuthorizationTimestamp";

    public static final String VERSION = "2.0";

    /**
     * The Authorization provider
     */
    protected String realm;
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
     * @param realm Authorization provider
     * @param accessKey Access Key
     * @param secretKey Secret Key
     * @param algorithmName Name of Algorithm
     */
    public HMACHttpRequestInterceptor(String realm, String accessKey, String secretKey,
            String algorithmName) {
        this.realm = realm;
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
    public void setCustomHeaders(String[] customHeaders) {
        this.customHeaders = new ArrayList<String>(Arrays.asList(customHeaders));
    }

    /** 
     * Returns the custom header names to use when constructing the message.
     * 
     * @return The list of HTTP header names
     */
    public String[] getCustomHeaders() {
        return this.customHeaders.toArray(new String[this.customHeaders.size()]);
    }

    @Override
    public void process(HttpRequest request, HttpContext context)
            throws HttpException, IOException {
        HMACAuthorizationHeader authHeader = this.createHMACAuthorizationHeader();
        if (authHeader == null) {
            throw new HttpException(
                "Error: Invalid authHeader; one or more required attributes are not set.");
        }

        //add X-Authorization-Timestamp if not set
        Header xAuthorizationTimestampHeaderHeader = request.getFirstHeader(
            HMACMessageCreator.PARAMETER_X_AUTHORIZATION_TIMESTAMP);
        if (xAuthorizationTimestampHeaderHeader == null) {
            long unixTime = this.getCurrentUnixTime();
            request.setHeader(HMACMessageCreator.PARAMETER_X_AUTHORIZATION_TIMESTAMP,
                Long.toString(unixTime));
        }

        //check content length
        Header contentLengthHeader = request.getFirstHeader(
            HMACMessageCreator.PARAMETER_CONTENT_LENGTH);
        int contentLength = 0;
        if (contentLengthHeader != null) {
            contentLength = Integer.parseInt(contentLengthHeader.getValue());
        }
        if (contentLength > 0) {
            //add X-Authorization-Content-SHA256 if not set
            Header xAuthorizationContentSha256Header = request.getFirstHeader(
                HMACMessageCreator.PARAMETER_X_AUTHORIZATION_CONTENT_SHA256);
            if (xAuthorizationContentSha256Header == null) {
                if (request instanceof HttpEntityEnclosingRequest) {
                    final HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
                    if (entity != null) {
                        //request body can only be consumed once - so copy this somewhere
                        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        entity.writeTo(baos);
                        baos.flush();
                        baos.close();
                        String bodyHash = this.getBase64Sha256String(baos.toByteArray());
                        request.setHeader(
                            HMACMessageCreator.PARAMETER_X_AUTHORIZATION_CONTENT_SHA256, bodyHash);

                        //set the entity again so it is ready for further consumption
                        ((HttpEntityEnclosingRequest) request).setEntity(new HttpEntity() {
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
                            public InputStream getContent()
                                    throws IOException, IllegalStateException {
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

                            @Override
                            public void consumeContent() throws IOException {
                                entity.consumeContent();
                            }
                        });
                    }
                }
            }
        }

        //create signature
        HMACMessageCreator messageCreator = new HMACMessageCreator();
        String signableRequestMessage = messageCreator.createSignableRequestMessage(request,
            authHeader);
        String signedRequestMessage = "";
        try {
            signedRequestMessage = this.algorithm.encryptMessage(this.secretKey,
                signableRequestMessage);
        } catch(SignatureException e) {
            throw new IOException("Fail to sign request message", e);
        }

        authHeader.setSignature(signedRequestMessage);
        //add Authorization with encrypted signature
        request.setHeader(HMACMessageCreator.PARAMETER_AUTHORIZATION, authHeader.toString());

        //set context for response interceptor
        context.setAttribute(CONTEXT_HTTP_VERB, request.getRequestLine().getMethod().toUpperCase());
        context.setAttribute(CONTEXT_AUTH_HEADER, authHeader);
        context.setAttribute(CONTEXT_X_AUTHORIZATION_TIMESTAMP, request.getFirstHeader(
            HMACMessageCreator.PARAMETER_X_AUTHORIZATION_TIMESTAMP).getValue()); //this header is guaranteed to exist
    }

    /**
     * Helper method to create createHMACAuthorizationHeader
     * 
     * @return
     */
    protected HMACAuthorizationHeader createHMACAuthorizationHeader() {
        HMACAuthorizationHeader result = new HMACAuthorizationHeader(this.realm, this.accessKey,
            UUID.randomUUID().toString(), VERSION, this.customHeaders, /*signature*/null);
        if (result.isAuthorizationHeaderValid()) {
            return result;
        } else {
            return null;
        }
    }

    /**
     * get current unix timestamp in seconds
     * @return
     */
    protected long getCurrentUnixTime() {
        long unixTime = System.currentTimeMillis() / 1000L;
        return unixTime;
    }

    /**
     * Get base64 encoded SHA-256 of an inputStreamBytes
     * 
     * @param inputStreamBytes
     * @return
     * @throws IOException
     */
    protected String getBase64Sha256String(byte[] inputStreamBytes) throws IOException {
        byte[] encBody = DigestUtils.sha256(inputStreamBytes);
        String bodyHash = Base64.encodeBase64String(encBody);
        return bodyHash;
    }

}
