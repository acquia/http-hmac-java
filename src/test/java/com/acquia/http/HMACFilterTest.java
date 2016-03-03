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

import org.junit.Before;
import org.junit.Test;

public class HMACFilterTest {

    private final String id = "f0d16792-cdc9-4585-a5fd-bae3d898d8c5";
    private final String secretKey = "eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==";

    private HttpServletRequest request;
    private CharResponseWrapper wrappedResponse;
    private FilterChain filterChain;

    @Before
    public void setup() throws IOException, ServletException {
        //base Authorization parameter
        String realm = "Plexus";

        String nonce = "64d02132-40bf-4fce-85bf-3f1bb1bfe7dd";
        String version = "2.0";
        String xAuthorizationTimestamp = "1449578521";

        String httpMethod = "POST";
        //        String uri = "http://54.154.147.142:3000/register";
        //        String secretKey = "eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==";

        String contentType = "application/json";
        String xAuthorizationContentSha256 = "6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo=";
        String reqBody = "{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}";

        String signature = "4VtBHjqrdDeYrJySoJVDUHpN9u3vyTsyOLz4chezi98=";

        HMACAuthorizationHeader authHeader = new HMACAuthorizationHeader(realm, id, nonce, version, /*headers*/
        null, signature);

        final ByteArrayInputStream realInputStream = new ByteArrayInputStream(reqBody.getBytes());
        ServletInputStream requestInputStream = new ServletInputStream() {
            @Override
            public int read() {
                return realInputStream.read();
            }
        };

        this.request = mock(HttpServletRequest.class);
        when(this.request.getHeader(HMACMessageCreator.PARAMETER_AUTHORIZATION)).thenReturn(
            authHeader.toString());
        when(this.request.getHeader(HMACMessageCreator.PARAMETER_X_AUTHORIZATION_TIMESTAMP)).thenReturn(
            xAuthorizationTimestamp);
        when(this.request.getHeader(HMACMessageCreator.PARAMETER_X_AUTHORIZATION_CONTENT_SHA256)).thenReturn(
            xAuthorizationContentSha256);

        when(this.request.getMethod()).thenReturn(httpMethod);
        when(this.request.getServerName()).thenReturn("54.154.147.142:3000");
        when(this.request.getRequestURI()).thenReturn("/register");
        when(this.request.getQueryString()).thenReturn("");

        when(this.request.getContentLength()).thenReturn(
            reqBody.getBytes(HMACMessageCreator.ENCODING_UTF_8).length);
        when(this.request.getContentType()).thenReturn(contentType);
        when(this.request.getInputStream()).thenReturn(requestInputStream);

        this.wrappedResponse = mock(CharResponseWrapper.class);
        this.filterChain = mock(FilterChain.class);
    }

    @Test
    public void testSuccessFilter() throws IOException, ServletException {
        HMACFilter testFilter = new HMACFilter() {
            @Override
            protected String getSecretKey(String accessKey) {
                if (id.equals(accessKey)) {
                    return secretKey;
                }
                return null;
            }
        };
        FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter("algorithm")).thenReturn("SHA256");
        testFilter.init(filterConfig);
        testFilter.doFilter(this.request, this.wrappedResponse, this.filterChain);

        verify(filterChain).doFilter(this.request, this.wrappedResponse);
    }

    @Test
    public void testFailureFilter() throws IOException, ServletException {
        HMACFilter testFilter = new HMACFilter() {
            @Override
            protected String getSecretKey(String accessKey) {
                if (id.equals(accessKey)) {
                    return "other-key";
                }
                return null;
            }
        };
        FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter("algorithm")).thenReturn("SHA256");
        testFilter.init(filterConfig);
        testFilter.doFilter(this.request, this.wrappedResponse, this.filterChain);

        verify(wrappedResponse).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED),
            (String) anyObject());
        verify(filterChain, never()).doFilter(request, wrappedResponse);
    }

}
