package com.acquia.http;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * The main class to allow modifications to request body
 * 
 * @author aric.tatan
 *
 */
public class CharRequestWrapper extends HttpServletRequestWrapper {

    public static final String ENCODING_UTF_8 = "UTF-8";

    /**
     * Helper class to allow getting ServletInputStream
     * 
     * @author aric.tatan
     *
     */
    public static class ByteArrayServletStream extends ServletInputStream {
        ByteArrayInputStream bais;

        ByteArrayServletStream(ByteArrayInputStream bais) {
            this.bais = bais;
        }

        @Override
        public int read() throws IOException {
            return bais.read();
        }
    }

    private ByteArrayServletStream input;
    private ByteArrayOutputStream baos = new ByteArrayOutputStream();

    public CharRequestWrapper(HttpServletRequest request) throws IOException {
        super(request);
        InputStream inputStream = request.getInputStream();

        byte[] byteChunk = new byte[1024];
        int length = -1;

        while ((length = inputStream.read(byteChunk)) != -1) {
            baos.write(byteChunk, 0, length);
        }
        baos.flush();
        baos.close();

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        this.input = new ByteArrayServletStream(bais);

    }

    public void resetInputStream() {
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        this.input = new ByteArrayServletStream(bais);
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        return this.input;
    }

    @Override
    public BufferedReader getReader() throws IOException {
        Reader reader = new InputStreamReader(this.input);
        return new BufferedReader(reader);
    }

}
