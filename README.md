# HTTP HMAC Signer for Java

An implementation of the [HTTP HMAC Spec](https://github.com/acquia/http-hmac-spec)
in Java.

## Client

The HMAC Authorization header can be added to an HTTP request by using the 
Apache HTTP Client and the com.acquia.http.HMACHttpRequestInterceptor. To configure
the HMACHttpRequestInterceptor, the constructor takes four arguments:

1. Provider
2. Access Key
3. Secret Key
4. HMAC Algorithm (ex. SHA1)

If custom headers should be added to the message that will encrypted then use the
'HMACHttpRequestInterceptor#setCustomHeaders' method to include them.

Example: Added the authorization header for the provider = Acquia, access key = 1, secret key = secret-key 
and customer headers = 'Custom1' using the algorithm = 'SHA1'

```
HMACHttpRequestInterceptor authorizationInterceptor = new HMACHttpRequestInterceptor("Acquia", "1", "secret-key", "SHA1");
authorizationInterceptor.setCustomHeaders(new String[] { "Custom1" } );

// Added the authorization header interceptor as the last interceptor for the 
// HttpClient
CloseableHttpClient httpClient = HttpClientBuilder.create().addInterceptorLast( authorizationInterceptor ).build();

String httpRequestUrl = ""; // todo: the request url
HttpGet httpGet = new HttpGet(httpRequestUrl);

// The authorization header will be added during the execute call
// before the request is sent
HttpResponse httpResponse = httpClient.execute(httpGet); 

// todo: normal processing of response

```