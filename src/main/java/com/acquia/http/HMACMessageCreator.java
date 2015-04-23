package com.acquia.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

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
    
    /**
     * Create the message based on the given HTTP request received and list of custom headers.
     * 
     * @param request HTTP request
     * @param customHeaders List of custom header names
     * @return The message to be encrypted
     * @throws IOException If the body can not be read or the MD5 of the body can not be created
     */
    public String createMessage(HttpServletRequest request, List<String> customHeaders) throws IOException {
        String httpVerb = request.getMethod();
        InputStream requestBody = request.getInputStream();
        String contentType = request.getHeader("Content-Type");
        String date = request.getHeader("Date");
        Map<String,String> customHeaderValues = new HashMap<String,String>();
        for ( String customHeaderName : customHeaders ) {
            String customHeaderValue = request.getHeader(customHeaderName);
            if ( customHeaderValue == null ) {
                continue;
            }
            customHeaderValues.put(customHeaderName,customHeaderValue);
        }
        StringBuilder resourceBuilder = new StringBuilder( request.getRequestURI() );
       
        String requestQuery = request.getQueryString();
        if ( requestQuery != null ) {
            resourceBuilder.append("?");
            resourceBuilder.append(requestQuery);
        }
        
        return createMessage(httpVerb, requestBody, contentType, date, customHeaderValues, resourceBuilder.toString());
    }
    
    /**
     * Create the message based on the given HTTP request to be sent and the list of custom header names.
     * 
     * @param request HTTP request
     * @param customHeaders The list of custom header names
     * @return The message to be encrypted
     * 
     * @throws IOException If the body can not be read or the MD5 of the body can not be created
     */
    protected String createMessage(HttpRequest request, List<String> customHeaders) throws IOException {
        String httpVerb = request.getRequestLine().getMethod().toUpperCase();
        InputStream requestBody = null;
        if ( request instanceof HttpEntityEnclosingRequest ) {
            HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
            requestBody = entity.getContent();
        }
        String contentType = request.getFirstHeader("Content-Type").getValue();
        // TODO: x-acquia-timestamp instead of Date
        String date = request.getFirstHeader("Date").getValue();
        Map<String,String> customHeaderValues = new HashMap<String,String>();
        for ( String customHeaderName : customHeaders ) {
            Header customHeader = request.getFirstHeader(customHeaderName);
            if ( customHeader == null ) {
                continue;
            }
            customHeaderValues.put(customHeaderName, customHeader.getValue());
        }
        String resource = null;
        try {
            URI uri = new URI(request.getRequestLine().getUri() );
            StringBuilder resourceBuilder = new StringBuilder( uri.getPath() );
            if ( uri.getQuery() != null ) {
                resourceBuilder.append("?");
                resourceBuilder.append(uri.getQuery());
            }
            resource = resourceBuilder.toString();
        }
        catch (URISyntaxException e ) {
            throw new IOException("Invalid URI", e);
        }
        
        return createMessage(httpVerb, requestBody, contentType, date, customHeaderValues, resource);
    }
    
    /**
     * Create the message based on the given components of the request.
     * 
     * @param httpVerb HTTP Verb
     * @param requestBody Request Body
     * @param contentType Request Body Content-Type
     * @param date Date of the Request
     * @param customHeaders Map of custom header names to values
     * @param resource Resource (including parameters) of the Request
     * @return The message to be encrypted
     * @throws IOException If the MD5 of the body can not be created
     */
    private String createMessage( String httpVerb, InputStream requestBody, String contentType, String date, Map<String,String> customHeaders, String resource ) throws IOException {
        StringBuilder returnMessage = new StringBuilder();
        returnMessage.append(httpVerb.toUpperCase());
        returnMessage.append("\n");
        if ( requestBody != null ) {
            String result = DigestUtils.md5Hex( requestBody );
            returnMessage.append(result);
            returnMessage.append("\n");
        }
        returnMessage.append(contentType);
        returnMessage.append("\n");
        // TODO: x-acquia-timestamp instead of Date
        returnMessage.append(date);
        returnMessage.append("\n");
        List<String> sortedKeyList = new ArrayList<String>(customHeaders.keySet());
        Collections.sort(sortedKeyList);
        for ( String customHeaderKey : sortedKeyList ) {
            returnMessage.append(customHeaderKey.toLowerCase());
            returnMessage.append(": ");
            returnMessage.append(customHeaders.get(customHeaderKey));
            returnMessage.append("\n");            
        }
        returnMessage.append( resource );
        return returnMessage.toString();        
    }
}
