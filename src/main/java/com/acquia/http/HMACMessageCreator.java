package com.acquia.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;

/**
 * The HMACMessageCreator is a utility class to create messages that will be encrypted into HMACs.
 * 
 * @author chris.nagy
 *
 */
public class HMACMessageCreator {

    private static final String PARAMETER_AUTHORIZATION = "Authorization";
    private static final String PARAMETER_X_AUTHORIZATION_TIMESTAMP = "X-Authorization-Timestamp";
    private static final String PARAMETER_CONTENT_TYPE = "Content-Type";

    private final List<String> baseHeaderNames = Arrays.asList("id", "nonce", "realm", "version");
    private final String customHeaderName = "headers";

    /**
     * Create the message based on the given HTTP request received and list of custom headers.
     * 
     * @param request HTTP request
     * @return The message to be encrypted
     * @throws IOException if bodyHash cannot be created
     */
    public String createMessage(HttpServletRequest request) throws IOException {
        String httpVerb = request.getMethod().toUpperCase();

        String host = request.getServerName();
        String path = request.getRequestURI();
        String queryParameters = request.getQueryString();
        if (queryParameters == null) {
            queryParameters = "";
        }

        String authorization = request.getHeader(PARAMETER_AUTHORIZATION);
        Map<String, String> authorizationParameterMap = HMACUtil.convertAuthorizationIntoParameterMap(authorization);

        Map<String, String> authorizationHeaderParameterMap = HMACUtil.buildBaseHeaderMap(
            authorizationParameterMap, this.baseHeaderNames);
        Map<String, String> authorizationCustomHeaderParameterMap = HMACUtil.buildCustomHeaderMap(
            request, authorizationParameterMap.get(this.customHeaderName));

        String xAuthorizationTimestamp = request.getHeader(PARAMETER_X_AUTHORIZATION_TIMESTAMP);
        String contentType = request.getHeader(PARAMETER_CONTENT_TYPE);
        InputStream requestBody = request.getInputStream();

        return this.createMessage(httpVerb, host, path, queryParameters,
            authorizationHeaderParameterMap, authorizationCustomHeaderParameterMap,
            xAuthorizationTimestamp, contentType, requestBody);
    }

    /**
     * Create the message based on the given HTTP request to be sent and the list of custom header names.
     * 
     * @param request HTTP request
     * @return The message to be encrypted
     * @throws IOException if bodyHash cannot be created
     */
    protected String createMessage(HttpRequest request) throws IOException {
        String httpVerb = request.getRequestLine().getMethod().toUpperCase();

        String host = "";
        String path = "";
        String queryParameters = "";
        try {
            URI uri = new URI(request.getRequestLine().getUri());
            host = uri.getHost();
            path = uri.getPath();
            queryParameters = uri.getQuery();
            if (queryParameters == null) {
                queryParameters = "";
            }
        } catch(URISyntaxException e) {
            throw new IOException("Invalid URI", e);
        }

        String authorization = request.getFirstHeader(PARAMETER_AUTHORIZATION).getValue();
        Map<String, String> authorizationParameterMap = HMACUtil.convertAuthorizationIntoParameterMap(authorization);

        Map<String, String> authorizationHeaderParameterMap = HMACUtil.buildBaseHeaderMap(
            authorizationParameterMap, this.baseHeaderNames);
        Map<String, String> authorizationCustomHeaderParameterMap = HMACUtil.buildCustomHeaderMap(
            request, authorizationParameterMap.get(this.customHeaderName));

        String xAuthorizationTimestamp = request.getFirstHeader(PARAMETER_X_AUTHORIZATION_TIMESTAMP).getValue();
        String contentType = request.getFirstHeader(PARAMETER_CONTENT_TYPE).getValue();

        InputStream requestBody = null;
        if (request instanceof HttpEntityEnclosingRequest) {
            HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
            requestBody = entity.getContent();
        }

        return this.createMessage(httpVerb, host, path, queryParameters,
            authorizationHeaderParameterMap, authorizationCustomHeaderParameterMap,
            xAuthorizationTimestamp, contentType, requestBody);
    }

    /**
     * Create the message based on the given components of the request.
     * 
     * @param httpVerb; HTTP request method (GET, POST, etc)
     * @param host; HTTP "Host" request header field (including any port number)
     * @param path; HTTP request path with leading slash '/'
     * @param queryParameters; exact string sent by the client, including urlencoding, without leading question mark '?'
     * @param authorizationHeaderParameterMap; Map (key, value) of Authorization header for: "realm", "id", "nonce", "version"
     * @param authorizationCustomHeaderParameterMap; Map (key, value) of Authorization header for: "headers" - other custom signed headers
     * @param xAuthorizationTimestamp; value of X-Authorization-Timestamp header
     * @param contentType; value of Content-Type header
     * @param requestBody; request body
     * @return The message to be encrypted
     * @throws IOException if bodyHash cannot be created
     */
    private String createMessage(String httpVerb, String host, String path, String queryParameters,
            Map<String, String> authorizationHeaderParameterMap,
            Map<String, String> authorizationCustomHeaderParameterMap,
            String xAuthorizationTimestamp, String contentType, InputStream requestBody)
            throws IOException {

        StringBuilder result = new StringBuilder();

        //adding request URI information
        result.append(httpVerb.toUpperCase()).append("\n");
        result.append(host.toLowerCase()).append("\n");
        result.append(path).append("\n");
        result.append(queryParameters).append("\n");

        //adding Authorization header parameters
        List<String> sortedKeyList = new ArrayList<String>(authorizationHeaderParameterMap.keySet());
        Collections.sort(sortedKeyList);
        boolean isFirst = true;
        for (String headerKey : sortedKeyList) {
            if (!isFirst) {
                result.append("&");
            }
            result.append(headerKey.toLowerCase()).append("=").append(
                authorizationHeaderParameterMap.get(headerKey));
            isFirst = false;
        }
        result.append("\n");

        //adding Authorization custom header parameters
        List<String> sortedCustomKeyList = new ArrayList<String>(
            authorizationCustomHeaderParameterMap.keySet());
        Collections.sort(sortedCustomKeyList);
        for (String headerKey : sortedCustomKeyList) {
            result.append(headerKey.toLowerCase()).append(":").append(
                authorizationCustomHeaderParameterMap.get(headerKey)).append("\n");
        }

        //adding X-Authorization-Timestamp
        result.append(xAuthorizationTimestamp);

        //adding more if needed
        String requestBodyString = this.convertInputStreamIntoString(requestBody);
        if (this.isPassingRequestBody(httpVerb, requestBodyString)) {
            result.append("\n").append(contentType);

            //calculate body hash
            String bodyHash = DigestUtils.sha256Hex(requestBodyString); //v2 specification requires base64 encoded SHA-256
            result.append("\n").append(bodyHash);
        }
        System.out.println(result);
        return result.toString();
    }

    /**
     * Convert InputStream into String
     * 
     * @param inputStream
     * @return
     */
    private String convertInputStreamIntoString(InputStream inputStream) {
        // Here we have used delimiter as "\A" which is boundary match for beginning of the input as declared in java.util.regex.Pattern
        //  and that's why Scanner is returning whole String form InputStream.
        // Source: http://javarevisited.blogspot.ca/2012/08/convert-inputstream-to-string-java-example-tutorial.html
        Scanner scanner = new Scanner(inputStream, "UTF-8");
        String inputStreamString = scanner.useDelimiter("\\A").next();
        scanner.close();
        return inputStreamString;
    }

    /**
     * Method to help check if requestBody needs to be passed or can be omitted
     * 
     * @param httpVerb
     * @param requestBodyString
     * @return
     */
    private boolean isPassingRequestBody(String httpVerb, String requestBodyString) {
        if (httpVerb.toUpperCase().equals("GET") || httpVerb.toUpperCase().equals("HEAD")) {
            return false;
        }

        return requestBodyString != null && requestBodyString.length() > 0;
    }
}
