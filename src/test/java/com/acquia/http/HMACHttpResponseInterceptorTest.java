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
        String realm = "Plexus";
        String id = "f0d16792-cdc9-4585-a5fd-bae3d898d8c5";
        String nonce = "64d02132-40bf-4fce-85bf-3f1bb1bfe7dd";
        String version = "2.0";
        String xAuthorizationTimestamp = "1449578521";

        String secretKey = "eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==";

        String respBody = "{\"person\":{\"id\":12007,\"engagementScore\":0,\"lastTouch\":\"2015-10-20T14:19:13Z\",\"firstTouch\":\"2015-10-20T14:19:13Z\",\"firstTimeVisitor\":true,\"subscriberStatus\":\"Unknown\",\"customerId\":10008,\"primaryIdentifier\":\"7RBYAsUXsXH6L5V871y0RO\",\"primaryIdentifierTypeId\":2,\"active\":true,\"lastModifiedDate\":\"2015-10-20T18:19:20Z\",\"anonymousVisitor\":false,\"doNotTrack\":false},\"identifiers\":[{\"id\":12611,\"identifier\":\"qa100\",\"personIdentifierTypeId\":6,\"personId\":12007,\"customerId\":10008,\"active\":true},{\"id\":12610,\"identifier\":\"qa100@example.com\",\"personIdentifierTypeId\":1,\"personId\":12007,\"customerId\":10008,\"active\":true},{\"id\":12609,\"identifier\":\"7RBYAsUXsXH6L5V871y0RO\",\"personIdentifierTypeId\":2,\"personId\":12007,\"customerId\":10008,\"active\":true}],\"touches\":[{\"id\":12212,\"touchDuration\":0,\"touchDurationInSeconds\":0,\"touchDate\":\"2015-10-20T14:19:13Z\",\"channelType\":\"twitter\",\"engagementScore\":0,\"referrer\":\"Direct\",\"referrerDomain\":\"Direct\",\"numberOfPageViews\":1,\"identifier\":\"33tpvFowlnHW7rNquqtmq5\",\"lastModifiedDate\":\"2015-10-20T18:19:20Z\",\"personId\":12007,\"customerId\":10008,\"personIdentifierId\":12609,\"events\":[{\"id\":17619,\"name\":\"Content View\",\"eventDate\":\"2015-10-20T14:19:13Z\",\"eventCategoryType\":\"OTHER\",\"accountId\":\"SOMEACCOUNTID\",\"referrer\":\"Direct\",\"captureIdentifier\":\"2zkT5TXrcC92HmKqMAq1Yc\",\"touchId\":12212,\"personId\":12007,\"customerId\":10008,\"eventCategoryId\":10046,\"clientDate\":\"2015-10-20T14:19:13Z\",\"clientTimezone\":\"America/Anguilla\",\"lastModifiedDate\":\"2015-10-20T18:19:20Z\"}]}]}";

        String expectedServerAuthResponseSignature = "3uUNS0PW5+fl6x1ZCcHxnt0Me0PWvtNBGsH5F17P+h8=";

        //mock response
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

        //mock context
        HttpContext context = mock(HttpContext.class);
        when(context.getAttribute("authHeader")).thenReturn(
            new HMACAuthorizationHeader(realm, id, nonce, version));
        when(context.getAttribute("xAuthorizationTimestamp")).thenReturn(xAuthorizationTimestamp);

        //test response interceptor
        HMACHttpResponseInterceptor responseInterceptor = new HMACHttpResponseInterceptor(
            secretKey, "SHA256");
        responseInterceptor.process(response, context); //this will throw HttpException if not passed
    }

    private Header mockHeader(String value) {
        Header header = mock(Header.class);
        when(header.getValue()).thenReturn(value);
        return header;
    }
}
