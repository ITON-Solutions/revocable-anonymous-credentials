/*
 *
 *  The MIT License
 *
 *  Copyright 2019 ITON Solutions.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */
package org.iton.jssi.ursa.rlp.util;


import org.iton.jssi.ursa.util.Bytes;

import java.util.Arrays;
import java.util.Base64;

/**
 * Utility for encoding and decoding hexadecimal, Base64, and UTF-8-encoded {@code String}s.
 */
public final class Strings {

    public static final int BASE_64 = 3; // 64
    public static final int DECIMAL = 2; // 10
    public static final int UTF_8 = 1; // 256
    public static final int HEX = 0; // 16

     public static String encode(byte[] bytes) {
        return encode(bytes, HEX);
    }

    public static String encode(byte[] bytes, int encoding) {
        return encode(bytes, 0, bytes.length, encoding);
    }

    public static String encode(byte[] buffer, int from, int len, int encoding) {
        byte[] src = Arrays.copyOfRange(buffer, from, from + len);
        switch (encoding) {
        case BASE_64: return Base64.getEncoder().encodeToString(src);
        case DECIMAL: return Decimal.encodeToString(buffer, from, len);
        case UTF_8: return new String(src);
        case HEX:
        default: return Bytes.toHex(src);
        }
    }

    public static byte[] decode(String encoded) {
        return decode(encoded, HEX);
    }

    public static byte[] decode(String string, int encoding) {
        if(string.isEmpty()) {
            return new byte[0];
        }
        switch (encoding) {
        case BASE_64: return java.util.Base64.getUrlDecoder().decode(string);
        case DECIMAL: return Decimal.decode(string, 0, string.length());
        case UTF_8: return string.getBytes();
        case HEX:
        default: return Bytes.toBytes(string);
        }
    }
}
