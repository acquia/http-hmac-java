package com.acquia.http;

import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;

public class HMACFilterTest {

    @Test
    public void testSuccessFilter() throws IOException, ServletException {
        //base Authorization parameter
        String realm = "Plexus";
        String accessKey = "f0d16792-cdc9-4585-a5fd-bae3d898d8c5";
        String nonce = "64d02132-40bf-4fce-85bf-3f1bb1bfe7dd";
        String version = "2.0";
        String xAuthorizationTimestamp = "1449578521";

        String httpMethod = "POST";
        String uri = "http://54.154.147.142:3000/register";
        String secretKey = "eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==";

        String contentType = "application/json";
        String reqBody = "{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}";

        String signature = "4VtBHjqrdDeYrJySoJVDUHpN9u3vyTsyOLz4chezi98=";

        HMACFilter testFilter = new HMACFilter() {

            @Override
            protected String getSecretKey(String accessKey) {
                if ("f0d16792-cdc9-4585-a5fd-bae3d898d8c5".equals(accessKey)) {
                    return "eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==";
                }
                return null;
            }
        };
        FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter("algorithm")).thenReturn("SHA256");
        testFilter.init(filterConfig);

        StringBuilder authBuilder = HMACUtil.constructAuthorizationString(realm, accessKey, nonce,
            version, /*headers*/null, signature);

        final ByteArrayInputStream realInputStream = new ByteArrayInputStream(reqBody.getBytes());
        ServletInputStream requestInputStream = new ServletInputStream() {
            @Override
            public int read() {
                return realInputStream.read();
            }
        };

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn(authBuilder.toString());
        when(request.getHeader("X-Authorization-Timestamp")).thenReturn(xAuthorizationTimestamp);
        when(request.getMethod()).thenReturn(httpMethod);
        when(request.getServerName()).thenReturn("54.154.147.142:3000");
        when(request.getRequestURI()).thenReturn("/register");
        when(request.getQueryString()).thenReturn("");
        when(request.getContentType()).thenReturn(contentType);
        when(request.getInputStream()).thenReturn(requestInputStream);

        HttpServletResponse response = mock(HttpServletResponse.class);

        FilterChain filterChain = mock(FilterChain.class);
        testFilter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void testFailureFilter() throws IOException, ServletException {
        //base Authorization parameter
        String realm = "Plexus";
        String accessKey = "f0d16792-cdc9-4585-a5fd-bae3d898d8c5";
        String nonce = "64d02132-40bf-4fce-85bf-3f1bb1bfe7dd";
        String version = "2.0";
        String xAuthorizationTimestamp = "1449578521";

        String httpMethod = "POST";
        String uri = "http://54.154.147.142:3000/register";
        String secretKey = "eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==";

        String contentType = "application/json";
        String reqBody = "{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}";

        String signature = "4VtBHjqrdDeYrJySoJVDUHpN9u3vyTsyOLz4chezi98=";

        HMACFilter testFilter = new HMACFilter() {

            @Override
            protected String getSecretKey(String accessKey) {
                if ("f0d16792-cdc9-4585-a5fd-bae3d898d8c5".equals(accessKey)) {
                    return "other-key"; //invalid bogus key
                }
                return null;
            }
        };
        FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter("algorithm")).thenReturn("SHA256");
        testFilter.init(filterConfig);

        StringBuilder authBuilder = HMACUtil.constructAuthorizationString(realm, accessKey, nonce,
            version, /*headers*/null, signature);

        final ByteArrayInputStream realInputStream = new ByteArrayInputStream(reqBody.getBytes());
        ServletInputStream requestInputStream = new ServletInputStream() {
            @Override
            public int read() {
                return realInputStream.read();
            }
        };

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn(authBuilder.toString());
        when(request.getHeader("X-Authorization-Timestamp")).thenReturn(xAuthorizationTimestamp);
        when(request.getMethod()).thenReturn(httpMethod);
        when(request.getServerName()).thenReturn("54.154.147.142:3000");
        when(request.getRequestURI()).thenReturn("/register");
        when(request.getQueryString()).thenReturn("");
        when(request.getContentType()).thenReturn(contentType);
        when(request.getInputStream()).thenReturn(requestInputStream);

        HttpServletResponse response = mock(HttpServletResponse.class);

        FilterChain filterChain = mock(FilterChain.class);
        testFilter.doFilter(request, response, filterChain);

        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), (String) anyObject());
        verify(filterChain, never()).doFilter(request, response);
    }
}
