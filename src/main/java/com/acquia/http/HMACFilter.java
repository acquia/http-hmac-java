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

/**
 * Abstract Filter that can validate HTTP requests by the HMAC Authorization header.
 * 
 * @author chris.nagy
 *
 */
public abstract class HMACFilter implements Filter {

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
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        if (req instanceof HttpServletRequest) {
            HttpServletRequest request = (HttpServletRequest) req;
            HttpServletResponse response = (HttpServletResponse) res;

            String authorization = request.getHeader("Authorization");
            if (authorization != null) {
                HMACAuthorizationHeader authHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(authorization);

                String accessKey = authHeader.getId();
                String signature = authHeader.getSignature();

                String secretKey = getSecretKey(accessKey);

                HMACMessageCreator messageCreator = new HMACMessageCreator(authHeader);
                String message = messageCreator.createMessage(request);
                try {
                    String calculatedSignature = this.algorithm.encryptMessage(secretKey, message);
                    if (signature.compareTo(calculatedSignature) != 0) {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                            "Error: Invalid authentication token.");
                        return;
                    } else {
                        chain.doFilter(req, res);
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
    }

    @Override
    public void destroy() {

    }

    /** 
     * Returns the secret key for the given access key.
     * 
     * @param accessKey Access Key
     * @return Secret Key
     */
    protected abstract String getSecretKey(String accessKey);
}
