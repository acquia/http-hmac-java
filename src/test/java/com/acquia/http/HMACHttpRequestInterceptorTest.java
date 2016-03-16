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
    public void testGetAuthorizationHeader() throws IOException, HttpException {
        //base Authorization parameter
        String realm = "Pipet service";
        String id = "efdde334-fe7b-11e4-a322-1697f925ec7b";
        String nonce = "d1954337-5319-4821-8427-115542e08d10";
        String version = "2.0";
        String xAuthorizationTimestamp = "1432075982";

        String httpMethod = "GET";
        String hostPort = "example.acquiapipet.net";
        String uri = "/v1.0/task-status/133?limit=10";
        String secretKey = "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=";

        String expectedSignature = "MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc=";

        final HMACAuthorizationHeader authHeader = new HMACAuthorizationHeader(realm, id, nonce,
            version);

        HMACHttpRequestInterceptor authorizationInterceptor = new HMACHttpRequestInterceptor(realm,
            id, secretKey, "SHA256") {

            @Override
            protected HMACAuthorizationHeader createHMACAuthorizationHeader() {
                return authHeader;
            }

        };
        authorizationInterceptor.setCustomHeaders(new String[] {});

        HttpEntityEnclosingRequest request = mock(HttpEntityEnclosingRequest.class);

        RequestLine requestLine = mock(RequestLine.class);
        when(requestLine.getMethod()).thenReturn(httpMethod);
        when(requestLine.getUri()).thenReturn(uri);
        when(request.getRequestLine()).thenReturn(requestLine);

        HttpEntity requestEntity = mock(HttpEntity.class);
        when(request.getEntity()).thenReturn(requestEntity);

        Header hostPortHeader = mockHeader(hostPort);
        when(request.getFirstHeader(HMACMessageCreator.PARAMETER_HOST)).thenReturn(hostPortHeader);
        Header xAuthorizationTimestampHeader = mockHeader(xAuthorizationTimestamp);
        when(request.getFirstHeader(HMACMessageCreator.PARAMETER_X_AUTHORIZATION_TIMESTAMP)).thenReturn(
            xAuthorizationTimestampHeader);

        HttpContext context = mock(HttpContext.class);

        final StringBuilder calcAuthorizationHeader = new StringBuilder();
        doAnswer(new Answer<Void>() {
            public Void answer(InvocationOnMock invocation) {
                Object[] args = invocation.getArguments();
                String headerKey = (String) args[0];
                String valueKey = (String) args[1];
                if (HMACMessageCreator.PARAMETER_AUTHORIZATION.equals(headerKey)) {
                    calcAuthorizationHeader.append(valueKey);
                }
                return null;
            }
        }).when(request).setHeader((String) anyObject(), (String) anyObject());

        authorizationInterceptor.process(request, context);

        HMACAuthorizationHeader calculatedAuthHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(calcAuthorizationHeader.toString());
        Assert.assertEquals(expectedSignature, calculatedAuthHeader.getSignature());
    }

    @Test
    public void testPostAuthorizationHeader() throws IOException, HttpException {
        //base Authorization parameter
        String realm = "Plexus";
        String id = "f0d16792-cdc9-4585-a5fd-bae3d898d8c5";
        String nonce = "64d02132-40bf-4fce-85bf-3f1bb1bfe7dd";
        String version = "2.0";
        String xAuthorizationTimestamp = "1449578521";

        String httpMethod = "POST";
        String hostPort = "54.154.147.142:3000";
        String uri = "/register";
        String secretKey = "eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==";

        String contentType = "application/json";
        String xAuthorizationContentSha256 = "6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo=";
        String reqBody = "{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}";

        String expectedSignature = "4VtBHjqrdDeYrJySoJVDUHpN9u3vyTsyOLz4chezi98=";

        final HMACAuthorizationHeader authHeader = new HMACAuthorizationHeader(realm, id, nonce,
            version);

        HMACHttpRequestInterceptor authorizationInterceptor = new HMACHttpRequestInterceptor(realm,
            id, secretKey, "SHA256") {

            @Override
            protected HMACAuthorizationHeader createHMACAuthorizationHeader() {
                return authHeader;
            }

        };
        authorizationInterceptor.setCustomHeaders(new String[] {});

        HttpEntityEnclosingRequest request = mock(HttpEntityEnclosingRequest.class);

        RequestLine requestLine = mock(RequestLine.class);
        when(requestLine.getMethod()).thenReturn(httpMethod);
        when(requestLine.getUri()).thenReturn(uri);
        when(request.getRequestLine()).thenReturn(requestLine);

        final ByteArrayInputStream realInputStream = new ByteArrayInputStream(reqBody.getBytes());
        InputStream requestInputStream = new InputStream() {
            @Override
            public int read() {
                return realInputStream.read();
            }
        };
        HttpEntity requestEntity = mock(HttpEntity.class);
        when(requestEntity.getContent()).thenReturn(requestInputStream);
        when(request.getEntity()).thenReturn(requestEntity);

        Header hostPortHeader = mockHeader(hostPort);
        when(request.getFirstHeader(HMACMessageCreator.PARAMETER_HOST)).thenReturn(hostPortHeader);
        Header contentLengthHeader = mockHeader(Integer.toString(reqBody.getBytes(HMACMessageCreator.ENCODING_UTF_8).length));
        when(request.getFirstHeader(HMACMessageCreator.PARAMETER_CONTENT_LENGTH)).thenReturn(
            contentLengthHeader);
        Header contentTypeHeader = mockHeader(contentType);
        when(request.getFirstHeader(HMACMessageCreator.PARAMETER_CONTENT_TYPE)).thenReturn(
            contentTypeHeader);
        Header xAuthorizationContentSha256Header = mockHeader(xAuthorizationContentSha256);
        when(request.getFirstHeader(HMACMessageCreator.PARAMETER_X_AUTHORIZATION_CONTENT_SHA256)).thenReturn(
            xAuthorizationContentSha256Header);
        Header xAuthorizationTimestampHeader = mockHeader(xAuthorizationTimestamp);
        when(request.getFirstHeader(HMACMessageCreator.PARAMETER_X_AUTHORIZATION_TIMESTAMP)).thenReturn(
            xAuthorizationTimestampHeader);
        HttpContext context = mock(HttpContext.class);

        final StringBuilder calcAuthorizationHeader = new StringBuilder();
        doAnswer(new Answer<Void>() {
            public Void answer(InvocationOnMock invocation) {
                Object[] args = invocation.getArguments();
                String headerKey = (String) args[0];
                String valueKey = (String) args[1];
                if (HMACMessageCreator.PARAMETER_AUTHORIZATION.equals(headerKey)) {
                    calcAuthorizationHeader.append(valueKey);
                }
                return null;
            }
        }).when(request).setHeader((String) anyObject(), (String) anyObject());

        authorizationInterceptor.process(request, context);

        HMACAuthorizationHeader calculatedAuthHeader = HMACAuthorizationHeader.getAuthorizationHeaderObject(calcAuthorizationHeader.toString());
        Assert.assertEquals(expectedSignature, calculatedAuthHeader.getSignature());
    }

    private Header mockHeader(String value) {
        Header header = mock(Header.class);
        when(header.getValue()).thenReturn(value);
        return header;
    }
}
