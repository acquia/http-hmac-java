package com.acquia.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.Header;
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

    public static final String ENCODING_UTF_8 = "UTF-8";

    public static final String PARAMETER_AUTHORIZATION = "Authorization";
    public static final String PARAMETER_X_AUTHORIZATION_TIMESTAMP = "X-Authorization-Timestamp";
    public static final String PARAMETER_X_AUTHORIZATION_CONTENT_SHA256 = "X-Authorization-Content-SHA256";
    public static final String PARAMETER_CONTENT_LENGTH = "Content-Length";
    public static final String PARAMETER_CONTENT_TYPE = "Content-Type";

    public static final String PARAMETER_HOST = "Host";

    public static final String PARAMETER_X_SERVER_AUTHORIZATION_HMAC_SHA256 = "X-Server-Authorization-HMAC-SHA256";

    /**
     * Constructor
     */
    public HMACMessageCreator() {
        super();
    }

    /**
     * Create response signature message
     * 
     * @param request HTTP request
     * @return The message to be encrypted
     * @throws IOException if bodyHash cannot be created
     */
    public String createSignableRequestMessage(HttpServletRequest request) throws IOException {
        String httpVerb = request.getMethod().toUpperCase();

        int port = request.getServerPort();
        String host = request.getServerName() + (port > 0 ? ":" + port : "");
        String path = request.getRequestURI();
        String queryParameters = request.getQueryString();
        if (queryParameters == null) {
            queryParameters = "";
        }

        String authorization = request.getHeader(PARAMETER_AUTHORIZATION);
        HMACAuthorizationHeader authHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(authorization);

        Map<String, String> authorizationCustomHeaderParameterMap = this.getCustomHeaderMap(
            authHeader, request);

        String xAuthorizationTimestamp = request.getHeader(PARAMETER_X_AUTHORIZATION_TIMESTAMP);
        int contentLength = request.getContentLength();
        String contentType = request.getContentType();
        String xAuthorizationContentSha256 = request.getHeader(PARAMETER_X_AUTHORIZATION_CONTENT_SHA256);
        InputStream requestBody = request.getInputStream();

        return this.createSignableRequestMessage(httpVerb, host, path, queryParameters, authHeader,
            authorizationCustomHeaderParameterMap, xAuthorizationTimestamp, contentLength,
            contentType, xAuthorizationContentSha256, requestBody);
    }

    /**
     * Create a key-value pair Map with custom headers of the Authorization
     * The pairs are constructed by grabbing the value by its header name in request object
     * 
     * @param authHeader
     * @param request
     * @return
     */
    private Map<String, String> getCustomHeaderMap(HMACAuthorizationHeader authHeader,
            HttpServletRequest request) {
        Map<String, String> theMap = new HashMap<String, String>();
        List<String> customHeaders = authHeader.getHeaders();
        if (customHeaders != null && customHeaders.size() > 0) {
            for (String headerName : customHeaders) {
                String headerValue = request.getHeader(headerName);
                if (headerValue == null) {
                    continue; //FIXME: throw error? custom parameter cannot be found
                }
                theMap.put(headerName.toLowerCase(), headerValue);
            }
        }
        return theMap;
    }

    /**
     * Create response signature message
     * 
     * @param request; HTTP request
     * @param authHeader; specify authHeader
     * @return The message to be encrypted
     * @throws IOException if bodyHash cannot be created
     */
    protected String createSignableRequestMessage(HttpRequest request, HMACAuthorizationHeader authHeader)
            throws IOException {
        String httpVerb = request.getRequestLine().getMethod().toUpperCase();

        String host = request.getFirstHeader(PARAMETER_HOST).getValue();
        String path = "";
        String queryParameters = "";
        try {
            URI uri = new URI(request.getRequestLine().getUri());
            path = uri.getPath();
            queryParameters = uri.getQuery();
            if (queryParameters == null) {
                queryParameters = "";
            }
        } catch(URISyntaxException e) {
            throw new IOException("Invalid URI", e);
        }

        //if authHeader is not set, try setting it from request
        if (authHeader == null) {
            String authorization = request.getFirstHeader(PARAMETER_AUTHORIZATION).getValue();
            authHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(authorization);
        }

        Map<String, String> authorizationCustomHeaderParameterMap = this.getCustomHeaderMap(
            authHeader, request);

        String xAuthorizationTimestamp = request.getFirstHeader(PARAMETER_X_AUTHORIZATION_TIMESTAMP).getValue();

        //optional content length
        Header contentLengthHeader = request.getFirstHeader(PARAMETER_CONTENT_LENGTH);
        int contentLength = 0;
        if (contentLengthHeader != null) {
            contentLength = Integer.parseInt(contentLengthHeader.getValue());
        }

        //optional content type
        Header contentTypeHeader = request.getFirstHeader(PARAMETER_CONTENT_TYPE);
        String contentType = "";
        if (contentTypeHeader != null) {
            contentType = contentTypeHeader.getValue();
        }

        //optional authorization content sha256
        Header xAuthorizationContentSha256Header = request.getFirstHeader(PARAMETER_X_AUTHORIZATION_CONTENT_SHA256);
        String xAuthorizationContentSha256 = "";
        if (xAuthorizationContentSha256Header != null) {
            xAuthorizationContentSha256 = xAuthorizationContentSha256Header.getValue();
        }

        //optional request body
        InputStream requestBody = null;
        if (request instanceof HttpEntityEnclosingRequest) {
            HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
            if (entity != null) {
                requestBody = entity.getContent();
                //if contentLength is still 0, try setting it from entity
                if (contentLength == 0) {
                    contentLength = (int) entity.getContentLength();
                }
            }
        }

        return this.createSignableRequestMessage(httpVerb, host, path, queryParameters, authHeader,
            authorizationCustomHeaderParameterMap, xAuthorizationTimestamp, contentLength,
            contentType, xAuthorizationContentSha256, requestBody);
    }

    /**
     * Create a key-value pair Map with custom headers of the Authorization
     * The pairs are constructed by grabbing the value by its header name in request object
     * 
     * @param authHeader
     * @param request
     * @return
     */
    private Map<String, String> getCustomHeaderMap(HMACAuthorizationHeader authHeader,
            HttpRequest request) {
        Map<String, String> theMap = new HashMap<String, String>();
        List<String> customHeaders = authHeader.getHeaders();
        if (customHeaders != null && customHeaders.size() > 0) {
            for (String headerName : customHeaders) {
                Header customHeader = request.getFirstHeader(headerName);
                if (customHeader == null) {
                    continue; //FIXME: throw error? custom parameter cannot be found
                }
                theMap.put(headerName.toLowerCase(), customHeader.getValue());
            }
        }
        return theMap;
    }

    /**
     * Helper method to create request signature message
     * 
     * @param httpVerb; HTTP request method (GET, POST, etc)
     * @param host; HTTP "Host" request header field (including any port number)
     * @param path; HTTP request path with leading slash '/'
     * @param queryParameters; exact string sent by the client, including urlencoding, without leading question mark '?'
     * @param authHeader; Authorization header that contains essential header information
     * @param authorizationCustomHeaderParameterMap; Map (key, value) of Authorization header for: "headers" - other custom signed headers
     * @param xAuthorizationTimestamp; value of X-Authorization-Timestamp header
     * @param contentLength; length of request body
     * @param contentType; value of Content-Type header
     * @param xAuthorizationContentSha256; encrypted body hash for request body
     * @param requestBody; request body
     * @return The message to be encrypted
     * @throws IOException if bodyHash cannot be created
     */
    private String createSignableRequestMessage(String httpVerb, String host, String path, String queryParameters,
            HMACAuthorizationHeader authHeader,
            Map<String, String> authorizationCustomHeaderParameterMap,
            String xAuthorizationTimestamp, int contentLength, String contentType,
            String xAuthorizationContentSha256, InputStream requestBody) throws IOException {

        StringBuilder result = new StringBuilder();

        //adding request URI information
        result.append(httpVerb.toUpperCase()).append("\n");
        result.append(host.toLowerCase()).append("\n");
        result.append(path).append("\n");
        result.append(queryParameters).append("\n");

        //adding Authorization header parameters
        result.append("id=").append(authHeader.getId());
        result.append("&nonce=").append(authHeader.getNonce());
        result.append("&realm=").append(
            URLEncoder.encode(authHeader.getRealm(), ENCODING_UTF_8).replace("+", "%20"));
        result.append("&version=").append(authHeader.getVersion());
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
        if (this.isPassingRequestBody(contentLength, xAuthorizationContentSha256, requestBody)) {
            result.append("\n").append(contentType.toLowerCase());
            result.append("\n").append(xAuthorizationContentSha256);
        }
        return result.toString();
    }

    /**
     * Method to help check if requestBody needs to be passed or can be omitted
     * 
     * @param xAuthorizationContentSha256
     * @param contentLength
     * @return
     * @throws IOException 
     */
    private boolean isPassingRequestBody(int contentLength, String xAuthorizationContentSha256,
            InputStream requestBody) throws IOException {
        if (contentLength <= 0 || xAuthorizationContentSha256 == null
                || xAuthorizationContentSha256.length() <= 0 || requestBody == null) {
            return false;
        }

        //calculate and check body hash
        byte[] requestBodyBytes = this.convertInputStreamIntoBtyeArray(requestBody);
        byte[] encBody = DigestUtils.sha256(requestBodyBytes);
        String bodyHash = Base64.encodeBase64String(encBody); //v2 specification requires base64 encoded SHA-256
        return bodyHash.equals(xAuthorizationContentSha256);
    }

    /**
     * Convert InputStream into byte[]
     * 
     * @param inputStream
     * @return
     * @throws IOException 
     */
    private byte[] convertInputStreamIntoBtyeArray(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            return null;
        }

        byte[] byteChunk = new byte[1000];
        int length = -1;

        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        while ((length = inputStream.read(byteChunk)) != -1) {
            byteOutputStream.write(byteChunk, 0, length);
        }
        byteOutputStream.flush();
        byteOutputStream.close();
        return byteOutputStream.toByteArray();
    }

    /**
     * Create response signature message
     * 
     * @param nonce
     * @param xAuthorizationTimestamp
     * @param responseContent
     * @return
     */
    public String createSignableResponseMessage(String nonce, String xAuthorizationTimestamp, String responseContent) {
        if (responseContent == null) {
            responseContent = "";
        }

        StringBuilder result = new StringBuilder();
        result.append(nonce).append("\n");
        result.append(xAuthorizationTimestamp).append("\n");
        result.append(responseContent);
        return result.toString();
    }

}
