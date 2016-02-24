package com.acquia.http;

import java.io.IOException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.StringTokenizer;

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
     * The config parameter that defines a comma-separated list of custom HTTP headers 
     * that are used in the construction of the encrypted message.
     */
    public static final String SERVLET_CONFIG_CUSTOMER_HEADERS = "customHeaders";

    /**
     * The config parameter that defines the name of the algorithm used the encrypt the message.
     */
    public static final String SERVLET_CONFIG_ALGORITHM = "algorithm";

    /**
     * The Algorithm used to create the HMAC.
     */
    HMACAlgorithm algorithm;

    /**
     * The list of custom HTTP headers used to construct the message that will be encrypted.
     */
    List<String> customHeaders = new ArrayList<String>();

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        String customHeadersList = config.getInitParameter(SERVLET_CONFIG_CUSTOMER_HEADERS);
        this.customHeaders = new ArrayList<String>(Arrays.asList(customHeadersList.split(",")));
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
