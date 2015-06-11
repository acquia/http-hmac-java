# HTTP HMAC Signer for Java

An implementation of the [HTTP HMAC Spec](https://github.com/acquia/http-hmac-spec)
in Java.

## Client

The HMAC Authorization header can be added to an HTTP request by using the 
Apache HTTP Client and the com.acquia.http.HMACHttpRequestInterceptor class.
To configure the HMACHttpRequestInterceptor, the constructor takes four arguments:

1. Provider
2. Access Key
3. Secret Key
4. HMAC Algorithm (ex. SHA1)

If custom headers need to be added to the message that will encrypted then 
specify their names by calling the 'HMACHttpRequestInterceptor#setCustomHeaders'
method.

Example: Add the authorization header for the provider = Acquia, access key = 1, secret key = secret-key 
and customer headers = 'Custom1' using the algorithm = 'SHA1'

```
HMACHttpRequestInterceptor authorizationInterceptor = new HMACHttpRequestInterceptor("Acquia", "1", "secret-key", "SHA1");
authorizationInterceptor.setCustomHeaders(new String[] { "Custom1" } );

// Added the authorization header interceptor as the last interceptor for the 
// HttpClient
CloseableHttpClient httpClient = HttpClientBuilder.create().addInterceptorLast( authorizationInterceptor ).build();

String httpRequestUrl = ""; // todo: the request url
HttpGet httpGet = new HttpGet(httpRequestUrl);

// The authorization header 'Acquia 1:0Qub9svYlxjAr8OO7N0/3u0sohs=' 
// will be added during the execute call, before the request is sent
HttpResponse httpResponse = httpClient.execute(httpGet); 

// todo: normal processing of response

```