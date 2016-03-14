package com.acquia.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * HMAC Utility class
 * 
 * @author aric.tatan
 *
 */
public abstract class HMACUtil {

    /**
     * Convert InputStream into byte[]
     * 
     * @param inputStream
     * @return
     * @throws IOException 
     */
    public static ByteArrayOutputStream convertInputStreamIntoByteArrayOutputStream(
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
