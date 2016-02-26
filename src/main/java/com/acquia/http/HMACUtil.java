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
     * Helper method to implode a list of Strings into a String
     * For example: List [ "a", "b" ] delimiter "," will become "a,b"
     * @param theList
     * @param glue
     * @return
     */
    public static String implodeStringArray(List<String> theList, String glue) {
        StringBuilder sBuilder = new StringBuilder();
        boolean isFirst = true;
        for (String aString : theList) {
            if (!isFirst) {
                sBuilder.append(glue);
            }
            sBuilder.append(aString);
            isFirst = false;
        }
        return sBuilder.toString();
    }

    /**
     * Create a key-value pair Map with custom headers of the Authorization
     * The pairs are constructed by grabbing the value by its header name in request object
     * 
     * @param authHeader
     * @param request
     * @return
     */
    public static Map<String, String> getCustomHeaderMap(HMACAuthorizationHeader authHeader,
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
     * Create a key-value pair Map with custom headers of the Authorization
     * The pairs are constructed by grabbing the value by its header name in request object
     * 
     * @param authHeader
     * @param request
     * @return
     */
    public static Map<String, String> getCustomHeaderMap(HMACAuthorizationHeader authHeader,
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

}
