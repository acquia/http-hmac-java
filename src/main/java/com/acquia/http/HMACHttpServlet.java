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

import org.apache.log4j.Logger;

/**
 * An abstract class that will validate the Authorization header based on the HMAC.
 * This will also append server validation response header.
 * 
 * @author chris.nagy
 */
@SuppressWarnings("serial")
public abstract class HMACHttpServlet extends HttpServlet {

    private static Logger logger = Logger.getLogger(HMACHttpServlet.class);

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
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            CharRequestWrapper wrappedRequest = new CharRequestWrapper(httpRequest);
            CharResponseWrapper wrappedResponse = new CharResponseWrapper(httpResponse);

            //upon entry
            boolean isAuthorized = this.validateRequestAuthorization(wrappedRequest,
                wrappedResponse);

            if (isAuthorized) {
                //reset input stream so it is ready to be consumed again
                wrappedRequest.resetInputStream();

                //do service
                this.doHmacService(wrappedRequest, wrappedResponse);

                //upon exit
                this.appendServerResponseValidation(wrappedRequest, wrappedResponse, httpResponse);
            }
        } else {
            super.service(request, response);
        }
    }

    /**
     * Helper method to validate request authorization
     * @param wrappedRequest
     * @param wrappedResponse
     * @return true if signature is correct; false otherwise
     * @throws IOException
     */
    private boolean validateRequestAuthorization(CharRequestWrapper wrappedRequest,
            CharResponseWrapper wrappedResponse) throws IOException {
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
                return false;
            } else if (timestampStatus < 0) {
                String message = "Error: X-Authorization-Timestamp is too far in the past.";
                logger.error(message);
                wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                return false;
            }
        } else {
            String message = "Error: X-Authorization-Timestamp is required.";
            logger.error(message);
            wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
            return false;
        }

        //check authorization
        String authorization = wrappedRequest.getHeader(HMACMessageCreator.PARAMETER_AUTHORIZATION);
        if (authorization != null) {
            HMACAuthorizationHeader authHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(
                authorization);
            if (authHeader == null) {
                String message = "Error: Invalid authHeader; one or more required attributes are not set.";
                logger.error(message);
                wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                return false;
            }

            String accessKey = authHeader.getId();
            String signature = authHeader.getSignature();

            String secretKey = null;
            try {
                secretKey = getSecretKey(accessKey);
            } catch(SecretKeyException skE) {
                String message = "Error: " + skE.getMessage();
                logger.error(message + "\n" + skE.getStackTrace());
                wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                return false;
            }

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
                return false;
            }
        } else {
            String message = "Error: Authorization is required.";
            logger.error(message);
            wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
            return false;
        }

        return true;
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
     * Call HttpServlet service method
     * 
     * @param wrappedRequest
     * @param wrappedResponse
     * @throws ServletException
     * @throws IOException
     */
    protected void doHmacService(CharRequestWrapper wrappedRequest,
            CharResponseWrapper wrappedResponse) throws ServletException, IOException {
        super.service(wrappedRequest, wrappedResponse);
    }

    /**
     * Helper method to append server response validation
     * 
     * @param wrappedRequest
     * @param wrappedResponse
     * @param httpResponse
     * @throws IOException
     */
    private void appendServerResponseValidation(CharRequestWrapper wrappedRequest,
            CharResponseWrapper wrappedResponse, HttpServletResponse httpResponse)
            throws IOException {
        String xAuthorizationTimestamp = wrappedRequest.getHeader(
            HMACMessageCreator.PARAMETER_X_AUTHORIZATION_TIMESTAMP);
        String authorization = wrappedRequest.getHeader(HMACMessageCreator.PARAMETER_AUTHORIZATION);
        if (authorization != null) {
            HMACAuthorizationHeader authHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(
                authorization);
            if (authHeader == null) {
                String message = "Error: Authorization is invalid.";
                logger.error(message);
                wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                return;
            }

            String accessKey = authHeader.getId();
            String nonce = authHeader.getNonce();

            String secretKey = null;
            try {
                secretKey = getSecretKey(accessKey);
            } catch(SecretKeyException skE) {
                String message = "Error: " + skE.getMessage();
                logger.error(message + "\n" + skE.getStackTrace());
                wrappedResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
                return;
            }

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
        }
    }

    /**
     * Returns the secret key for the given access key.
     * 
     * @param accessKey
     * @return
     * @throws SecretKeyException
     */
    protected abstract String getSecretKey(String accessKey) throws SecretKeyException;

}
