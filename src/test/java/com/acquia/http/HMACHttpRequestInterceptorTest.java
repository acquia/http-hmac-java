package com.acquia.http;

import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

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
        String accessKey = "ABCD-1234";
        String nonce = "c3df8396-b297-425f-c19c-634d6ca25d39";
        String version = "2.0";
        String xAuthorizationTimestamp = "1456417334";

        String secretKey = "d175024aa4c4d8b312a7114687790c772dd94fb725cb68016aaeae5a76d68102";

        HMACHttpRequestInterceptor authorizationInterceptor = new HMACHttpRequestInterceptor(realm,
            accessKey, secretKey, "SHA256");
        //        authorizationInterceptor.setCustomHeaders(new String[] { "Special-header-1",
        //                "Special-header-2" });
        authorizationInterceptor.setCustomHeaders(new String[] {});
        HttpEntityEnclosingRequest request = mock(HttpEntityEnclosingRequest.class);

        RequestLine requestLine = mock(RequestLine.class);
        when(requestLine.getMethod()).thenReturn("GET");
        when(requestLine.getUri()).thenReturn(
            "http://acquia.com/resource=1?first_word=Hello&second_word=World");
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
        authHeader.append("headers=\"").append("").append("\"");
        Header authorizationHeader = mockHeader(authHeader.toString());
        when(request.getFirstHeader("Authorization")).thenReturn(authorizationHeader);

        Header contentTypeHeader = mockHeader("text/plain");
        when(request.getFirstHeader("Content-Type")).thenReturn(contentTypeHeader);
        Header xAuthorizationTimestampHeader = mockHeader(xAuthorizationTimestamp);
        when(request.getFirstHeader("X-Authorization-Timestamp")).thenReturn(
            xAuthorizationTimestampHeader);
        Header custom1Header = mockHeader("special_header_1_value");
        when(request.getFirstHeader("Special-header-1")).thenReturn(custom1Header);
        Header custom2Header = mockHeader("special_header_2_value");
        when(request.getFirstHeader("Special-header-2")).thenReturn(custom2Header);

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
        }).when(request).setHeader((String) anyObject(), (String) anyObject());

        authorizationInterceptor.process(request, context);

        String calculatedAuthorization = calcAuthorizationHeader.toString();
        System.out.println("auth header\n" + calculatedAuthorization);
        Map<String, String> authorizationParameterMap = HMACUtil.convertAuthorizationIntoParameterMap(calculatedAuthorization);

        Assert.assertEquals("tgrFkCH7uSeUkPv9Z1FfyQBMPahiK8lRp/ecyp3BDys=",
            authorizationParameterMap.get("signature"));
    }

    private Header mockHeader(String value) {
        Header header = mock(Header.class);
        when(header.getValue()).thenReturn(value);
        return header;
    }
}
