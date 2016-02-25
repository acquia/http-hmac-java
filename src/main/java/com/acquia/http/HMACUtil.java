package com.acquia.http;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.Header;
import org.apache.http.HttpRequest;

/**
 * Utility class for Hmac project
 * 
 * @author aric.tatan
 *
 */
public class HMACUtil {

    /**
     * This method converts an Authorization string into a key-value pair Map
     * 
     * The input format:
     * acquia-http-hmac realm="Example",id="client-id",nonce="random-uuid",version="2.0",headers="custom1;custom2",signature="Signature"
     * 
     * The result of this call will be a Map in <key,value> pair of the parameters section (2nd token)
     * This will discard the 1st token (i.e.: acquia-http-hmac will be discarded)
     * 
     * @param authString; in the format specified above
     * @return
     */
    public static Map<String, String> convertAuthorizationIntoParameterMap(String authString) {
        int indexSpace = authString.indexOf(" ");
        String authContent = authString.substring(indexSpace + 1);
        String[] authParams = authContent.split(",");

        Map<String, String> theMap = new HashMap<String, String>();
        for (String param : authParams) {
            int indexDelimiter = param.indexOf("="); //first index of delimiter
            String key = param.substring(0, indexDelimiter);
            String val = param.substring(indexDelimiter + 1);
            theMap.put(key.toLowerCase(), val.substring(1, val.length() - 1)); //remove "" from val
        }
        return theMap;
    }

    /**
     * This method filters and picks up all key-pair values as specified from a list of baseHeaderNames
     * 
     * @param authorizationParameterMap
     * @param baseHeaderNames
     * @return
     */
    public static Map<String, String> buildBaseHeaderMap(
            Map<String, String> authorizationParameterMap, List<String> baseHeaderNames) {
        Map<String, String> theMap = new HashMap<String, String>();
        for (String headerName : baseHeaderNames) {
            String headerValue = authorizationParameterMap.get(headerName);
            if (headerValue == null) {
                continue; //FIXME: throw error? base parameters are all required
            }
            theMap.put(headerName.toLowerCase(), headerValue);
        }
        return theMap;
    }

    /**
     * This method builds Custom Header Map
     * Key-Value pairs are constructed by grabbing the value by its header name in request object
     * 
     * @param request
     * @param customHeaders; headers are separated by ";"
     * @return
     */
    public static Map<String, String> buildCustomHeaderMap(HttpServletRequest request,
            String customHeaders) {
        Map<String, String> theMap = new HashMap<String, String>();
        for (String headerName : customHeaders.split(";")) {
            String headerValue = request.getHeader(headerName);
            if (headerValue == null) {
                continue; //FIXME: throw error? custom parameter cannot be found
            }
            theMap.put(headerName.toLowerCase(), headerValue);
        }
        return theMap;
    }

    /**
     * This method builds Custom Header Map
     * Key-Value pairs are constructed by grabbing the value by its header name in request object
     * 
     * @param request
     * @param customHeaders; headers are separated by ";"
     * @return
     */
    public static Map<String, String> buildCustomHeaderMap(HttpRequest request, String customHeaders) {
        Map<String, String> theMap = new HashMap<String, String>();
        for (String headerName : customHeaders.split(";")) {
            Header customHeader = request.getFirstHeader(headerName);
            if (customHeader == null) {
                continue; //FIXME: throw error? custom parameter cannot be found
            }
            theMap.put(headerName.toLowerCase(), customHeader.getValue());
        }
        return theMap;
    }

}
