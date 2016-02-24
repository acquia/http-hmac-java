package com.acquia.http;

import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.RequestLine;
import org.apache.http.protocol.HttpContext;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class HMACHttpRequestInterceptorTest {

    @Test
    public void testAddAuthorizationHeader() throws IOException, HttpException {
        //base Authorization parameter
        String realm = "Acquia";
        String accessKey = "1";
        String nonce = "de305d54-75b4-431b-adb2-eb6b9e546014";
        String version = "2.0";

        HMACHttpRequestInterceptor authorizationInterceptor = new HMACHttpRequestInterceptor(realm,
            accessKey, "secret-key", "SHA1");
        authorizationInterceptor.setCustomHeaders(new String[] { "Custom1" });
        HttpEntityEnclosingRequest request = mock(HttpEntityEnclosingRequest.class);

        RequestLine requestLine = mock(RequestLine.class);
        when(requestLine.getMethod()).thenReturn("GET");
        when(requestLine.getUri()).thenReturn("http://acquia.com/resource/1?key=value");
        when(request.getRequestLine()).thenReturn(requestLine);

        final ByteArrayInputStream realInputStream = new ByteArrayInputStream(
            "test content".getBytes());
        InputStream requestInputStream = new InputStream() {
            @Override
            public int read() {
                return realInputStream.read();
            }
        };
        HttpEntity requestEntity = mock(HttpEntity.class);
        when(requestEntity.getContent()).thenReturn(requestInputStream);
        when(request.getEntity()).thenReturn(requestEntity);

        StringBuilder authHeader = new StringBuilder();
        authHeader.append("acquia-http-hmac realm=\"").append(realm).append("\",");
        authHeader.append("id=\"").append(accessKey).append("\",");
        authHeader.append("nonce=\"").append(nonce).append("\",");
        authHeader.append("version=\"").append(version).append("\",");
        authHeader.append("headers=\"").append("Custom1").append("\"");
        Header authorizationHeader = mockHeader(authHeader.toString());
        when(request.getFirstHeader("Authorization")).thenReturn(authorizationHeader);

        Header contentTypeHeader = mockHeader("text/plain");
        when(request.getFirstHeader("Content-Type")).thenReturn(contentTypeHeader);
        Header xAuthorizationTimestampHeader = mockHeader("1432075982");
        when(request.getFirstHeader("X-Authorization-Timestamp")).thenReturn(
            xAuthorizationTimestampHeader);
        Header custom1Header = mockHeader("Value1");
        when(request.getFirstHeader("Custom1")).thenReturn(custom1Header);

        HttpContext context = mock(HttpContext.class);

        final StringBuilder calcAuthorizationHeader = new StringBuilder();
        doAnswer(new Answer<Void>() {
            public Void answer(InvocationOnMock invocation) {
                Object[] args = invocation.getArguments();
                String headerKey = (String) args[0];
                String valueKey = (String) args[1];
                if ("Authorization".equals(headerKey)) {
                    calcAuthorizationHeader.append(valueKey);
                }
                return null;
            }
        }).when(request).addHeader((String) anyObject(), (String) anyObject());

        authorizationInterceptor.process(request, context);

        Assert.assertEquals("oqglS0eRzS1P2+R9AqqJUf4fNi0=", calcAuthorizationHeader.toString());
    }

    private Header mockHeader(String value) {
        Header header = mock(Header.class);
        when(header.getValue()).thenReturn(value);
        return header;
    }
}
