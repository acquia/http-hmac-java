package com.acquia.http;

import java.io.IOException;
import java.security.SignatureException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

/**
 * Abstract Filter that can validate HTTP requests by the HMAC Authorization header.
 * This will also append server validation response header.
 * 
 * @author chris.nagy
 *
 */
public abstract class HMACFilter implements Filter {

    private static Logger logger = Logger.getLogger(HMACFilter.class);

    /**
     * The config parameter that defines the name of the algorithm used to create the HMAC.
     */
    public static final String FILTER_CONFIG_ALGORITHM = "algorithm";

    /**
     * The Algorithm used to create the HMAC.
     */
    HMACAlgorithm algorithm;

    @Override
    public void init(FilterConfig config) throws ServletException {
        HMACAlgorithmFactory algorithmFactory = new HMACAlgorithmFactory();
        String algorithmName = config.getInitParameter(FILTER_CONFIG_ALGORITHM);
        this.algorithm = algorithmFactory.createAlgorithm(algorithmName);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            CharRequestWrapper wrappedRequest = new CharRequestWrapper(httpRequest);
            CharResponseWrapper wrappedResponse = new CharResponseWrapper(httpResponse);

            //check timestamp
            String xAuthorizationTimestamp = wrappedRequest.getHeader(
                HMACMessageCreator.PARAMETER_X_AUTHORIZATION_TIMESTAMP);
            if (xAuthorizationTimestamp != null) {
                int timestampStatus = this.compareTimestampWithinTolerance(
                    Long.parseLong(xAuthorizationTimestamp));
                if (timestampStatus > 0) {
                    String message = "Error: X-Authorization-Timestamp is too far in the future.";
                    logger.error(message);
                    wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                    return;
                } else if (timestampStatus < 0) {
                    String message = "Error: X-Authorization-Timestamp is too far in the past.";
                    logger.error(message);
                    wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                    return;
                }
            } else {
                String message = "Error: X-Authorization-Timestamp is required.";
                logger.error(message);
                wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                return;
            }

            //check authorization
            String authorization = wrappedRequest.getHeader(
                HMACMessageCreator.PARAMETER_AUTHORIZATION);
            if (authorization != null) {
                HMACAuthorizationHeader authHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(
                    authorization);
                if (authHeader == null) {
                    String message = "Error: Invalid authHeader; one or more required attributes are not set.";
                    logger.error(message);
                    wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                    return;
                }

                String accessKey = authHeader.getId();
                String nonce = authHeader.getNonce();
                String signature = authHeader.getSignature();

                String secretKey = getSecretKey(accessKey);

                //check request validity
                HMACMessageCreator messageCreator = new HMACMessageCreator();
                String signableRequestMessage = messageCreator.createSignableRequestMessage(
                    wrappedRequest);
                logger.trace("signableRequestMessage:\n" + signableRequestMessage);
                String signedRequestMessage = "";
                try {
                    signedRequestMessage = this.algorithm.encryptMessage(secretKey,
                        signableRequestMessage);
                    logger.trace("signedRequestMessage:\n" + signedRequestMessage);
                } catch(SignatureException e) {
                    String message = "Fail to sign request message";
                    logger.error(message);
                    throw new IOException(message, e);
                }

                if (signature.compareTo(signedRequestMessage) != 0) {
                    String message = "Error: Invalid authentication token.";
                    logger.error(message);
                    wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                    return;
                }

                //reset input stream so it is ready to be consumed again
                wrappedRequest.resetInputStream();

                //pass along to other filter
                chain.doFilter(wrappedRequest, wrappedResponse);

                //set response validation header
                String responseContent = wrappedResponse.toString();
                String signableResponseMessage = messageCreator.createSignableResponseMessage(nonce,
                    xAuthorizationTimestamp, responseContent);
                logger.trace("signableResponseMessage:\n" + signableResponseMessage);
                String signedResponseMessage = "";
                try {
                    signedResponseMessage = this.algorithm.encryptMessage(secretKey,
                        signableResponseMessage);
                    logger.trace("signedResponseMessage:\n" + signedResponseMessage);
                } catch(SignatureException e) {
                    String message = "Fail to sign response message";
                    logger.error(message);
                    throw new IOException(message, e);
                }
                wrappedResponse.setHeader(
                    HMACMessageCreator.PARAMETER_X_SERVER_AUTHORIZATION_HMAC_SHA256,
                    signedResponseMessage);
                httpResponse.getOutputStream().write(wrappedResponse.getByteArray()); //write back the response to the REAL HttpServletResponse
            } else {
                String message = "Error: Authorization is required.";
                logger.error(message);
                wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                return;
            }
        }
    }

    @Override
    public void destroy() {

    }

    /**
     * Check if timestamp is within tolerance (900 seconds)
     * 
     * @param unixTimestamp
     * @return non-zero if timestamp is outside tolerance (positive if in the future; negative in the past); otherwise return zero
     */
    protected int compareTimestampWithinTolerance(long unixTimestamp) {
        long tolerance = 900;
        long unixCurrent = System.currentTimeMillis() / 1000L;
        if (unixTimestamp > unixCurrent + tolerance) {
            return 1;
        } else if (unixTimestamp < unixCurrent - tolerance) {
            return -1;
        } else {
            return 0;
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
