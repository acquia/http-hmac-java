package com.acquia.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

/**
 * The main class to allow modifications to response body
 * http://stackoverflow.com/questions/14736328/looking-for-an-example-for-inserting-content-into-the-response-using-a-servlet-f
 * 
 * @author aric.tatan
 *
 */
public class CharResponseWrapper extends HttpServletResponseWrapper {

    public static final String ENCODING_UTF_8 = "UTF-8";

    /**
     * Helper class to allow getting ServletOutputStream
     * 
     * @author aric.tatan
     *
     */
    public static class ByteArrayServletStream extends ServletOutputStream {
        ByteArrayOutputStream baos;

        ByteArrayServletStream(ByteArrayOutputStream baos) {
            this.baos = baos;
        }

        public void write(int param) throws IOException {
            baos.write(param);
        }
    }

    /**
     * Helper class to allow options to pick between getWriter or getStream
     *  
     * @author aric.tatan
     *
     */
    private static class ByteArrayPrintWriter {
        private ByteArrayOutputStream baos = new ByteArrayOutputStream();
        private PrintWriter pw = new PrintWriter(baos);
        private ServletOutputStream sos = new ByteArrayServletStream(baos);

        public PrintWriter getWriter() {
            return pw;
        }

        public ServletOutputStream getStream() {
            return sos;
        }

        public byte[] toByteArray() {
            return baos.toByteArray();
        }

        @Override
        public String toString() {
            String result = "";
            try {
                result = new String(baos.toByteArray(), ENCODING_UTF_8);
            } catch(UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            return result;
        }
    }

    private ByteArrayPrintWriter output;

    public CharResponseWrapper(HttpServletResponse response) {
        super(response);
        output = new ByteArrayPrintWriter();
    }

    public byte[] getByteArray() {
        return output.toByteArray();
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        return output.getStream();
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        return output.getWriter();
    }

    @Override
    public String toString() {
        return output.toString();
    }

}
