package com.acquia.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.servlet.http.HttpServletRequest;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

public class HttpServletRequestMatcher extends BaseMatcher<HttpServletRequest> {

    private String content;

    public HttpServletRequestMatcher(String content) {
        this.content = content;
    }

    @Override
    public boolean matches(Object arg0) {
        boolean isTheSame = false;
        ByteArrayOutputStream baos = null;

        HttpServletRequest req = (HttpServletRequest) arg0;
        try {
            baos = this.convertInputStreamIntoByteArrayOutputStream(req.getInputStream());
            String baosString = baos.toString("UTF-8");
            isTheSame = baosString.equals(this.content);

        } catch(IOException e) {
            e.printStackTrace();
        }

        return isTheSame;
    }

    @Override
    public void describeTo(Description arg0) {
        arg0.appendText("Request InputStream = [" + this.content + "]");
    }

    /**
     * Convert InputStream into byte[]
     * 
     * @param inputStream
     * @return
     * @throws IOException 
     */
    private ByteArrayOutputStream convertInputStreamIntoByteArrayOutputStream(
            InputStream inputStream) throws IOException {
        if (inputStream == null) {
            return null;
        }

        byte[] byteChunk = new byte[1024];
        int length = -1;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((length = inputStream.read(byteChunk)) != -1) {
            baos.write(byteChunk, 0, length);
        }
        baos.flush();
        baos.close();
        return baos;
    }

}
