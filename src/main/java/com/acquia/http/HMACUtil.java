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

    /**
     * Check if timestamp is within tolerance (900 seconds)
     * 
     * @param unixTimestamp
     * @return non-zero if timestamp is outside tolerance (positive if in the future; negative in the past); otherwise return zero
     */
    public static int compareTimestampWithinTolerance(long unixTimestamp) {
        long tolerance = 900;
        long unixCurrent = System.currentTimeMillis() / 1000L;
        if (unixTimestamp > unixCurrent + tolerance) {
            return 1;
        } else if (unixTimestamp < unixCurrent - tolerance) {
            return -1;
        } else {
            return 0;
        }
    }

}
