package com.acquia.http;

import java.io.IOException;
import java.security.SignatureException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * An abstract class that will validate the Authorization header based on the HMAC.
 * This will also append server validation response header.
 * 
 * @author chris.nagy
 */
@SuppressWarnings("serial")
public abstract class HMACHttpServlet extends HttpServlet {

    /**
     * The config parameter that defines the name of the algorithm used the encrypt the message.
     */
    public static final String SERVLET_CONFIG_ALGORITHM = "algorithm";

    /**
     * The Algorithm used to create the HMAC.
     */
    HMACAlgorithm algorithm;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        HMACAlgorithmFactory algorithmFactory = new HMACAlgorithmFactory();
        String algorithmName = config.getInitParameter(SERVLET_CONFIG_ALGORITHM);
        this.algorithm = algorithmFactory.createAlgorithm(algorithmName);
    }

    @Override
    public void service(ServletRequest request, ServletResponse response)
            throws ServletException, IOException {
        //upon entry
        this.validateRequestAuthorization(request, response);

        //do service
        super.service(request, response);

        //upon exit
        this.appendServerResponseValidation(request, response);
    }

    /**
     * Helper method to validate request authorization
     * 
     * @param request
     * @param response
     * @throws IOException
     */
    private void validateRequestAuthorization(ServletRequest request, ServletResponse response)
            throws IOException {
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;

            //check timestamp
            String xAuthorizationTimestamp = httpRequest.getHeader(
                HMACMessageCreator.PARAMETER_X_AUTHORIZATION_TIMESTAMP);
            if (xAuthorizationTimestamp != null) {
                int timestampStatus = HMACUtil.compareTimestampWithinTolerance(
                    Long.parseLong(xAuthorizationTimestamp));
                if (timestampStatus > 0) {
                    httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                        "Error: X-Authorization-Timestamp is too far in the future.");
                    return;
                } else if (timestampStatus < 0) {
                    httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                        "Error: X-Authorization-Timestamp is too far in the past.");
                    return;
                }
            } else {
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Error: X-Authorization-Timestamp is required.");
                return;
            }

            //check authorization
            String authorization = httpRequest.getHeader(
                HMACMessageCreator.PARAMETER_AUTHORIZATION);
            if (authorization != null) {
                HMACAuthorizationHeader authHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(
                    authorization);

                String accessKey = authHeader.getId();
                String signature = authHeader.getSignature();

                String secretKey = getSecretKey(accessKey);

                //check request validity
                HMACMessageCreator messageCreator = new HMACMessageCreator();
                String signableRequestMessage = messageCreator.createSignableRequestMessage(
                    httpRequest);
                String signedRequestMessage = "";
                try {
                    signedRequestMessage = this.algorithm.encryptMessage(secretKey,
                        signableRequestMessage);
                } catch(SignatureException e) {
                    throw new IOException("Fail to sign request message", e);
                }

                if (signature.compareTo(signedRequestMessage) != 0) {
                    httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                        "Error: Invalid authentication token.");
                    return;
                }
            } else {
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Error: Authorization is required.");
                return;
            }
        }
    }

    /**
     * Helper method to append server response validation
     * 
     * @param request
     * @param response
     * @throws IOException
     */
    private void appendServerResponseValidation(ServletRequest request, ServletResponse response)
            throws IOException {
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            CharResponseWrapper wrappedResponse = new CharResponseWrapper(httpResponse);

            String xAuthorizationTimestamp = httpRequest.getHeader(
                HMACMessageCreator.PARAMETER_X_AUTHORIZATION_TIMESTAMP);
            String authorization = httpRequest.getHeader(
                HMACMessageCreator.PARAMETER_AUTHORIZATION);
            if (authorization != null) {
                HMACAuthorizationHeader authHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(
                    authorization);

                String accessKey = authHeader.getId();
                String nonce = authHeader.getNonce();

                String secretKey = getSecretKey(accessKey);

                //set response validation header
                HMACMessageCreator messageCreator = new HMACMessageCreator();
                String responseContent = wrappedResponse.toString();
                String signableResponseMessage = messageCreator.createSignableResponseMessage(nonce,
                    xAuthorizationTimestamp, responseContent);
                String signedResponseMessage = "";
                try {
                    signedResponseMessage = this.algorithm.encryptMessage(secretKey,
                        signableResponseMessage);
                } catch(SignatureException e) {
                    throw new IOException("Fail to sign response message", e);
                }
                httpResponse.setHeader(
                    HMACMessageCreator.PARAMETER_X_SERVER_AUTHORIZATION_HMAC_SHA256,
                    signedResponseMessage);
                httpResponse.getOutputStream().write(wrappedResponse.getByteArray()); //write back the response
            } else {
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Error: Authorization is required.");
            }
        }
    }

    /** 
     * Returns the secret key for the given access key.
     * 
     * @param accessKey Access Key
     * @return Secret Key
     */
    protected abstract String getSecretKey(String accessKey);

}
