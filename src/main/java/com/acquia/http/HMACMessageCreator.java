package com.acquia.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
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
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The HMACMessageCreator is a utility class to create messages that will be encrypted into HMACs.
 * 
 * @author chris.nagy
 *
 */
public class HMACMessageCreator {

    private static Logger logger = LogManager.getLogger(HMACMessageCreator.class);

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
     * Create request signature message from HTTP request
     * 
     * @param request HTTP request
     * @return The message to be encrypted
     * @throws IOException if bodyHash cannot be created
     */
    public String createSignableRequestMessage(HttpServletRequest request) throws IOException {
        String httpVerb = request.getMethod().toUpperCase();

        String host = request.getHeader(PARAMETER_HOST);
        String path = request.getRequestURI();
        String forwardedHost = request.getHeader("x-forwarded-host");
        String replacedPath = request.getHeader("x-replaced-path");
        if(forwardedHost != null && replacedPath != null) {
             host = getFirstHost(forwardedHost);
             path = replacedPath;
        }
        String queryParameters = request.getQueryString();
        logger.trace("Query string received: " + queryParameters);
        if (queryParameters == null) {
            queryParameters = "";
        }

        String authorization = request.getHeader(PARAMETER_AUTHORIZATION);
        HMACAuthorizationHeader authHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(
            authorization);
        if (authHeader == null) {
            String message = "Error: Invalid authHeader; one or more required attributes are not set.";
            logger.error(message);
            throw new IOException(message);
        }

        Map<String, String> authorizationCustomHeaderParameterMap = this.getCustomHeaderMap(
            authHeader, request);

        String xAuthorizationTimestamp = request.getHeader(PARAMETER_X_AUTHORIZATION_TIMESTAMP);
        int contentLength = request.getContentLength();
        String contentType = request.getContentType();
        String xAuthorizationContentSha256 = request.getHeader(
            PARAMETER_X_AUTHORIZATION_CONTENT_SHA256);
        InputStream requestBody = request.getInputStream();

        return this.createSignableRequestMessage(httpVerb, host, path, queryParameters, authHeader,
            authorizationCustomHeaderParameterMap, xAuthorizationTimestamp, contentLength,
            contentType, xAuthorizationContentSha256, requestBody);
    }

    String getFirstHost(String host){
        String[] hostArray = host.split("\\s*,\\s*");
        return hostArray[0];
    }



    /**
     * Create a key-value pair Map with custom headers of the Authorization
     * The pairs are constructed by grabbing the value by its header name in request object
     * 
     * @param authHeader
     * @param request
     * @return 
     * @throws IOException
     */
    private Map<String, String> getCustomHeaderMap(HMACAuthorizationHeader authHeader,
            HttpServletRequest request) throws IOException {
        Map<String, String> theMap = new HashMap<String, String>();
        List<String> customHeaders = authHeader.getHeaders();
        if (customHeaders != null && customHeaders.size() > 0) {
            for (String headerName : customHeaders) {
                String headerValue = request.getHeader(headerName);
                if (headerValue == null) {
                    String message = "Error: Custom header \"" + headerName
                            + "\" cannot be found in the HTTP request.";
                    logger.error(message);
                    throw new IOException(message);
                }
                theMap.put(headerName.toLowerCase(), headerValue);
            }
        }
        return theMap;
    }

    /**
     * Create request signature message from HTTP request
     * 
     * @param request; HTTP request
     * @param authHeader; specify authHeader
     * @return The message to be encrypted
     * @throws HttpException
     * @throws IOException if bodyHash cannot be created
     */
    protected String createSignableRequestMessage(HttpRequest request,
            HMACAuthorizationHeader authHeader) throws HttpException, IOException {
        String httpVerb = request.getRequestLine().getMethod().toUpperCase();

        String host = request.getFirstHeader(PARAMETER_HOST).getValue();
        String path = "";
        String queryParameters = "";
        try {
            URI uri = new URI(request.getRequestLine().getUri());
            path = uri.getPath();
            queryParameters = uri.getRawQuery();
            if (queryParameters == null) {
                queryParameters = "";
            }
        } catch(URISyntaxException e) {
            String message = "Error: Invalid URI.";
            logger.error(message);
            throw new HttpException(message, e);
        }

        //if authHeader is not set, try setting it from request
        if (authHeader == null) {
            String authorization = request.getFirstHeader(PARAMETER_AUTHORIZATION).getValue();
            authHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(authorization);
            if (authHeader == null) {
                String message = "Error: Invalid authHeader; one or more required attributes are not set.";
                logger.error(message);
                throw new HttpException(message);
            }
        }

        Map<String, String> authorizationCustomHeaderParameterMap = this.getCustomHeaderMap(
            authHeader, request);

        String xAuthorizationTimestamp = request.getFirstHeader(
            PARAMETER_X_AUTHORIZATION_TIMESTAMP).getValue();

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
        Header xAuthorizationContentSha256Header = request.getFirstHeader(
            PARAMETER_X_AUTHORIZATION_CONTENT_SHA256);
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
     * @throws HttpException 
     */
    private Map<String, String> getCustomHeaderMap(HMACAuthorizationHeader authHeader,
            HttpRequest request) throws HttpException {
        Map<String, String> theMap = new HashMap<String, String>();
        List<String> customHeaders = authHeader.getHeaders();
        if (customHeaders != null && customHeaders.size() > 0) {
            for (String headerName : customHeaders) {
                Header customHeader = request.getFirstHeader(headerName);
                if (customHeader == null) {
                    String message = "Error: Custom header \"" + headerName
                            + "\" cannot be found in the HTTP request.";
                    logger.error(message);
                    throw new HttpException(message);
                }
                theMap.put(headerName.toLowerCase(), customHeader.getValue());
            }
        }
        return theMap;
    }

    /**
     * Helper method to create request signature message from HTTP request attributes
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
    private String createSignableRequestMessage(String httpVerb, String host, String path,
            String queryParameters, HMACAuthorizationHeader authHeader,
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
        result.append("id=").append(this.escapeProper(authHeader.getId()));
        result.append("&nonce=").append(this.escapeProper(authHeader.getNonce()));
        result.append("&realm=").append(this.escapeProper(authHeader.getRealm()));
        result.append("&version=").append(this.escapeProper(authHeader.getVersion()));
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
            if (this.isValidRequestBody(xAuthorizationContentSha256, requestBody)) {
                result.append("\n").append(contentType.toLowerCase());
                result.append("\n").append(xAuthorizationContentSha256);
            } else {
                String message = "Error: Request body does not have the same hash as X-Authorization-Content-Sha256 header.";
                logger.error(message);
                throw new IOException(message);
            }
        }
        return result.toString();
    }

    /**
     * Escape String with UTF-8 encoding
     * 
     * @param theString
     * @return
     * @throws UnsupportedEncodingException
     */
    private String escapeProper(String theString) throws UnsupportedEncodingException {
        return URLEncoder.encode(theString, ENCODING_UTF_8).replace("+", "%20");
    }

    /**
     * Method to help check if requestBody is properly passed or not
     * 
     * @param contentLength
     * @param xAuthorizationContentSha256
     * @param requestBody
     * @return
     */
    private boolean isPassingRequestBody(int contentLength, String xAuthorizationContentSha256,
            InputStream requestBody) {
        if (contentLength <= 0 || xAuthorizationContentSha256 == null
                || xAuthorizationContentSha256.length() <= 0 || requestBody == null) {
            return false;
        }
        return true;
    }

    /**
     * Method to help check if requestBody has the same hash as specified
     * 
     * @param xAuthorizationContentSha256
     * @param requestBody
     * @return
     * @throws IOException 
     */
    private boolean isValidRequestBody(String xAuthorizationContentSha256, InputStream requestBody)
            throws IOException {
        if (xAuthorizationContentSha256 == null || xAuthorizationContentSha256.length() <= 0
                || requestBody == null) {
            return false;
        }

        //calculate and check body hash
        String bodyHash = this.getBase64Sha256String(requestBody); //v2 specification requires base64 encoded SHA-256
        return bodyHash.equals(xAuthorizationContentSha256);
    }

    /**
     * Get base64 encoded SHA-256 of an inputStream
     * 
     * @param inputStream
     * @return
     * @throws IOException
     */
    private String getBase64Sha256String(InputStream inputStream) throws IOException {
        byte[] inputStreamBytes = this.convertInputStreamIntoByteArrayOutputStream(
            inputStream).toByteArray();
        byte[] encBody = DigestUtils.sha256(inputStreamBytes);
        String bodyHash = Base64.encodeBase64String(encBody);
        return bodyHash;
    }

    /**
     * Convert InputStream into byte[]
     * 
     * @param inputStream
     * @return
     * @throws IOException 
     */
    private ByteArrayOutputStream convertInputStreamIntoByteArrayOutputStream(
            InputStream inputStream) throws IOException {
        if (inputStream == null) {
            return null;
        }

        byte[] byteChunk = new byte[1024];
        int length = -1;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((length = inputStream.read(byteChunk)) != -1) {
            baos.write(byteChunk, 0, length);
        }
        baos.flush();
        baos.close();
        return baos;
    }

    /**
     * Create response signature message from HTTP response attributes
     * 
     * @param nonce
     * @param xAuthorizationTimestamp
     * @param responseContent
     * @return
     */
    public String createSignableResponseMessage(String nonce, String xAuthorizationTimestamp,
            String responseContent) {
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
