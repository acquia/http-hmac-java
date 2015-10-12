package com.acquia.http;

import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.RequestLine;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.protocol.HttpContext;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class HMACHttpRequestInterceptorTest {

    
    @Test
    public void testAddAuthorizationHeader() throws IOException, HttpException {
        HMACHttpRequestInterceptor authorizationInterceptor = new HMACHttpRequestInterceptor("Acquia", "1", "secret-key", "SHA1");
        authorizationInterceptor.setCustomHeaders(new String[] { "Custom1" } );
        HttpEntityEnclosingRequest request = mock(HttpEntityEnclosingRequest.class);

        RequestLine requestLine = mock(RequestLine.class);
        when(requestLine.getMethod()).thenReturn("GET");
        when(requestLine.getUri()).thenReturn("/resource/1?key=value");
        when(request.getRequestLine()).thenReturn(requestLine);
        
        final ByteArrayInputStream realInputStream = new ByteArrayInputStream("test content".getBytes());
        InputStream requestInputStream = new InputStream() {
            @Override
            public int read() {
                return realInputStream.read();
            }
        };
        HttpEntity requestEntity = mock(HttpEntity.class);
        when(requestEntity.getContent()).thenReturn(requestInputStream);
        when(request.getEntity()).thenReturn(requestEntity);
        
        Header contentTypeHeader = mockHeader("text/plain" );
        when(request.getFirstHeader("Content-Type")).thenReturn(contentTypeHeader);
        Header dateHeader = mockHeader("Fri, 19 Mar 1982 00:00:04 GMT");
        when(request.getFirstHeader("Date")).thenReturn(dateHeader);
        Header custom1Header = mockHeader("Value1");
        when(request.getFirstHeader("Custom1")).thenReturn(custom1Header);

        HttpContext context = mock(HttpContext.class);
        
        final StringBuilder calcAuthorizationHeader = new StringBuilder();
        doAnswer(new Answer<Void>() {
            public Void answer(InvocationOnMock invocation) {
                Object[] args = invocation.getArguments();
                String headerKey = (String) args[0];
                String valueKey = (String) args[1];
                if ( "Authorization".equals( headerKey ) ) {
                    calcAuthorizationHeader.append( valueKey );
                }
                return null;
            }
        }).when(request).addHeader((String) anyObject(),
            (String) anyObject());
        
        authorizationInterceptor.process(request, context);

        //Assert.assertEquals( "Acquia 1:0Qub9svYlxjAr8OO7N0/3u0sohs=", calcAuthorizationHeader.toString() );     
    }

    private Header mockHeader(String value) {
        Header header = mock(Header.class);
        when(header.getValue()).thenReturn( value );
        return header;
    }
}
