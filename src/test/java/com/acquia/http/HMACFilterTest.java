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
        HMACFilter testFilter = new HMACFilter() {

            @Override
            protected String getSecretKey(String accessKey) {
                if ("1".equals(accessKey)) {
                    return "secret-key";
                }
                return null;
            }
        };
        FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter("customHeaders")).thenReturn("Custom1");
        when(filterConfig.getInitParameter("algorithm")).thenReturn("SHA256");
        testFilter.init(filterConfig);

        final ByteArrayInputStream realInputStream = new ByteArrayInputStream(
            "test content".getBytes());
        ServletInputStream requestInputStream = new ServletInputStream() {
            @Override
            public int read() {
                return realInputStream.read();
            }
        };

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("GET");
        when(request.getInputStream()).thenReturn(requestInputStream);
        when(request.getHeader("Content-Type")).thenReturn("text/plain");
        when(request.getHeader("X-Authorization-Timestamp")).thenReturn("1432075982");
        when(request.getHeader("Custom1")).thenReturn("Value1");
        when(request.getServerName()).thenReturn("acquia.com");
        when(request.getRequestURI()).thenReturn("/resource/1");
        when(request.getQueryString()).thenReturn("key=value");
        when(request.getHeader("Authorization")).thenReturn("Acquia 1:0Qub9svYlxjAr8OO7N0/3u0sohs=");

        HttpServletResponse response = mock(HttpServletResponse.class);

        FilterChain filterChain = mock(FilterChain.class);
        testFilter.doFilter(request, response, filterChain);

        //verify(response, never()).sendError(anyInt(), (String) anyObject());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void testFailureFilter() throws IOException, ServletException {
        HMACFilter testFilter = new HMACFilter() {

            @Override
            protected String getSecretKey(String accessKey) {
                if ("1".equals(accessKey)) {
                    return "other-key";
                }
                return null;
            }
        };
        FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter("customHeaders")).thenReturn("Custom1");
        when(filterConfig.getInitParameter("algorithm")).thenReturn("SHA256");
        testFilter.init(filterConfig);

        final ByteArrayInputStream realInputStream = new ByteArrayInputStream(
            "test content".getBytes());
        ServletInputStream requestInputStream = new ServletInputStream() {
            @Override
            public int read() {
                return realInputStream.read();
            }
        };

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("GET");
        when(request.getInputStream()).thenReturn(requestInputStream);
        when(request.getHeader("Content-Type")).thenReturn("text/plain");
        when(request.getHeader("X-Authorization-Timestamp")).thenReturn("1432075982");
        when(request.getHeader("Custom1")).thenReturn("Value1");
        when(request.getServerName()).thenReturn("acquia.com");
        when(request.getRequestURI()).thenReturn("/resource/1");
        when(request.getQueryString()).thenReturn("key=value");
        when(request.getHeader("Authorization")).thenReturn("Acquia 1:0Qub9svYlxjAr8OO7N0/3u0sohs=");

        HttpServletResponse response = mock(HttpServletResponse.class);

        FilterChain filterChain = mock(FilterChain.class);
        testFilter.doFilter(request, response, filterChain);

        verify(response).sendError(eq(HttpServletResponse.SC_UNAUTHORIZED), (String) anyObject());
        verify(filterChain, never()).doFilter(request, response);
    }
}
