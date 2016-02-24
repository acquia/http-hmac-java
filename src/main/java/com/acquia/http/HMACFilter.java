package com.acquia.http;

import java.io.IOException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.StringTokenizer;

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
     * The config parameter that defines a comma-separated list of custom HTTP headers 
     * that are used in the construction of the message that will be encrypted.
     */
    public static final String FILTER_CONFIG_CUSTOMER_HEADERS = "customHeaders";

    /**
     * The config parameter that defines the name of the algorithm used to create the HMAC.
     */
    public static final String FILTER_CONFIG_ALGORITHM = "algorithm";

    /**
     * The Algorithm used to create the HMAC.
     */
    HMACAlgorithm algorithm;

    /**
     * The list of custom HTTP headers used to construct the message that will be encrypted.
     */
    List<String> customHeaders;

    @Override
    public void init(FilterConfig config) throws ServletException {
        String customHeadersList = config.getInitParameter(FILTER_CONFIG_CUSTOMER_HEADERS);
        if (customHeadersList != null) {
            this.customHeaders = new ArrayList<String>(Arrays.asList(customHeadersList.split(",")));
        } else {
            this.customHeaders = new ArrayList<String>();
        }
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

            String authHeader = request.getHeader("Authorization");

            if (authHeader != null) {

                StringTokenizer st = new StringTokenizer(authHeader);

                if (st.hasMoreTokens()) {

                    String realm = st.nextToken();
                    String credentials = st.nextToken();
                    int index = credentials.indexOf(":");

                    if (index == -1) {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                            "Error: Invalid authentication token.");
                        return;
                    }

                    String accessKey = credentials.substring(0, index).trim();
                    String signature = credentials.substring(index + 1).trim();

                    String secretKey = getSecretKey(accessKey);

                    HMACMessageCreator messageCreator = new HMACMessageCreator();
                    String message = messageCreator.createMessage(request, this.customHeaders);
                    try {
                        String calculatedSignature = this.algorithm.encryptMessage(secretKey,
                            message);

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
