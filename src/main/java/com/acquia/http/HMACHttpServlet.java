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
    public void service(ServletRequest req, ServletResponse res) throws ServletException,
            IOException {
        if (req instanceof HttpServletRequest) {
            HttpServletRequest request = (HttpServletRequest) req;
            HttpServletResponse response = (HttpServletResponse) res;

            String authorization = request.getHeader("Authorization");
            if (authorization != null) {
                HMACAuthorizationHeader authHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(authorization);

                String accessKey = authHeader.getId();
                String signature = authHeader.getSignature();

                String secretKey = getSecretKey(accessKey);

                HMACMessageCreator messageCreator = new HMACMessageCreator();
                String message = messageCreator.createMessage(request);
                try {
                    String calculatedSignature = this.algorithm.encryptMessage(secretKey, message);
                    if (signature.compareTo(calculatedSignature) != 0) {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                            "Error: Invalid authentication token.");
                        return;
                    }
                } catch(SignatureException e) {
                    throw new IOException("Could not create calculated signature", e);
                }
            }

            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                "Error: No authentication credentials were found.");
            return;
        }
        super.service(req, res);
    }

    /** 
     * Returns the secret key for the given access key.
     * 
     * @param accessKey Access Key
     * @return Secret Key
     */
    protected abstract String getSecretKey(String accessKey);
}
