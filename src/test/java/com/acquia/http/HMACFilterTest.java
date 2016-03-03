package com.acquia.http;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.acquia.http.CharResponseWrapper.ByteArrayServletStream;

public class HMACFilterTest {

    private final String id = "f0d16792-cdc9-4585-a5fd-bae3d898d8c5";
    private final String secretKey = "eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==";

    private final String respBody = "{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}";
    private final String expectedServerAuthResponseSignature = "IxZYV49tP0GjbCZO0KDtk1eJSCMbObjfP+lYFc8NSxs=";

    private HttpServletRequest request;
    private FilterConfig filterConfig;

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

        this.filterConfig = mock(FilterConfig.class);
        when(this.filterConfig.getInitParameter("algorithm")).thenReturn("SHA256");
    }

    @Test
    public void testSuccessFilter() throws IOException, ServletException {
        //prepare output stream
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ServletOutputStream sos = new ByteArrayServletStream(baos);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getOutputStream()).thenReturn(sos);

        final StringBuilder serverResponseValidationHeader = new StringBuilder();
        doAnswer(new Answer<Void>() {
            public Void answer(InvocationOnMock invocation) {
                Object[] args = invocation.getArguments();
                String headerKey = (String) args[0];
                String valueKey = (String) args[1];
                if (HMACMessageCreator.PARAMETER_X_SERVER_AUTHORIZATION_HMAC_SHA256.equals(headerKey)) {
                    serverResponseValidationHeader.append(valueKey);
                }
                return null;
            }
        }).when(response).setHeader((String) anyObject(), (String) anyObject());

        //mock filterChain to return response body as specified
        FilterChain filterChain = mock(FilterChain.class);
        doAnswer(new Answer<Void>() {
            public Void answer(InvocationOnMock invocation) throws IOException {
                Object[] args = invocation.getArguments();
                //                HttpServletRequest request = (HttpServletRequest) args[0];
                HttpServletResponse response = (HttpServletResponse) args[1];
                response.getOutputStream().write(respBody.getBytes());
                return null;
            }
        }).when(filterChain).doFilter((HttpServletRequest) anyObject(),
            (HttpServletResponse) anyObject());

        //test the filter
        HMACFilter testFilter = new HMACFilter() {
            @Override
            protected String getSecretKey(String accessKey) {
                if (id.equals(accessKey)) {
                    return secretKey;
                }
                return null;
            }
        };
        testFilter.init(this.filterConfig);
        testFilter.doFilter(this.request, response, filterChain);

        verify(filterChain).doFilter((ServletRequest) anyObject(), (ServletResponse) anyObject());
        assertEquals(this.expectedServerAuthResponseSignature,
            serverResponseValidationHeader.toString());
    }

    @Test
    public void testFailureFilter() throws IOException, ServletException {
        //mock stuffs
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);

        //test filter
        HMACFilter testFilter = new HMACFilter() {
            @Override
            protected String getSecretKey(String accessKey) {
                if (id.equals(accessKey)) {
                    return "other-key";
                }
                return null;
            }
        };
        testFilter.init(this.filterConfig);
        testFilter.doFilter(this.request, response, filterChain);

        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), (String) anyObject());
        verify(filterChain, never()).doFilter(this.request, response);
    }

}
