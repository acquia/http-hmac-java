package com.acquia.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

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

    /**
     * Helper class to allow getting ServletOutputStream
     * 
     * @author aric.tatan
     *
     */
    private static class ByteArrayServletStream extends ServletOutputStream {
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

        byte[] toByteArray() {
            return baos.toByteArray();
        }
    }

    private ByteArrayPrintWriter output;
    private boolean usingWriter;

    public CharResponseWrapper(HttpServletResponse response) {
        super(response);
        usingWriter = false;
        output = new ByteArrayPrintWriter();
    }

    public byte[] getByteArray() {
        return output.toByteArray();
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        // will error out, if in use
        if (usingWriter) {
            super.getOutputStream();
        }
        usingWriter = true;
        return output.getStream();
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        // will error out, if in use
        if (usingWriter) {
            super.getWriter();
        }
        usingWriter = true;
        return output.getWriter();
    }

    @Override
    public String toString() {
        return output.toString();
    }

}
