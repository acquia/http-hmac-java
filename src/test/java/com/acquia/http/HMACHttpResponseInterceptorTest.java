package com.acquia.http;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.protocol.HttpContext;
import org.junit.Test;

public class HMACHttpResponseInterceptorTest {

    @Test
    public void testResponseValidationHeader() throws IOException, HttpException {
        //base Authorization parameter
        String nonce = "64d02132-40bf-4fce-85bf-3f1bb1bfe7dd";
        String xAuthorizationTimestamp = "1449578521";

        String secretKey = "eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==";

        String respBody = "{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}";

        String expectedServerAuthResponseSignature = "IxZYV49tP0GjbCZO0KDtk1eJSCMbObjfP+lYFc8NSxs=";

        HMACHttpResponseInterceptor responseInterceptor = new HMACHttpResponseInterceptor(nonce,
            xAuthorizationTimestamp, secretKey, "SHA256");

        HttpResponse response = mock(HttpResponse.class);

        final ByteArrayInputStream realInputStream = new ByteArrayInputStream(respBody.getBytes());
        InputStream responseInputStream = new InputStream() {
            @Override
            public int read() {
                return realInputStream.read();
            }
        };
        HttpEntity responseEntity = mock(HttpEntity.class);
        when(responseEntity.getContentLength()).thenReturn(
            Long.parseLong(respBody.getBytes(HMACMessageCreator.ENCODING_UTF_8).length + ""));
        when(responseEntity.getContent()).thenReturn(responseInputStream);
        when(response.getEntity()).thenReturn(responseEntity);

        Header xServerAuthorizationHmacSha256Header = mockHeader(expectedServerAuthResponseSignature);
        when(
            response.getFirstHeader(HMACMessageCreator.PARAMETER_X_SERVER_AUTHORIZATION_HMAC_SHA256)).thenReturn(
            xServerAuthorizationHmacSha256Header);

        HttpContext context = mock(HttpContext.class);

        responseInterceptor.process(response, context); //this will throw HttpException if not passed
    }

    private Header mockHeader(String value) {
        Header header = mock(Header.class);
        when(header.getValue()).thenReturn(value);
        return header;
    }
}
