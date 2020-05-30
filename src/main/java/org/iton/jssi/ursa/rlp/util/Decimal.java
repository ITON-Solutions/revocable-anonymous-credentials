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

public final class Decimal {

    private static final int NUM_BYTE_VALS = 1 << Byte.SIZE;
    private static final int CHARS_PER_BYTE = "255".length();
    private static final char[] ENCODING = new char[NUM_BYTE_VALS * CHARS_PER_BYTE];

    static {
        int j = 0;
        for (int i = 0; i < NUM_BYTE_VALS; i++) {
            String str = String.valueOf(i);
            int len = str.length();
            ENCODING[j++] = len == CHARS_PER_BYTE ? str.charAt(0) : '0';
            ENCODING[j++] = len >= 2 ? str.charAt(len - 2) : '0';
            ENCODING[j++] = str.charAt(len - 1);
        }
    }

    public static String encodeToString(byte[] buffer, int i, final int len) {
        char[] chars = new char[len * CHARS_PER_BYTE];
        final int end = i + len;
        for (int j = 0; i < end; ) {
            int idx = (buffer[i++] & 0xFF) * CHARS_PER_BYTE;
            chars[j++] = ENCODING[idx++];
            chars[j++] = ENCODING[idx++];
            chars[j++] = ENCODING[idx];
        }
        return new String(chars);
    }

    public static byte[] decode(String src, int i, final int len) {
        final int byteLen = len / CHARS_PER_BYTE;
        if(byteLen * CHARS_PER_BYTE != len) {
            throw new IllegalArgumentException("length must be a multiple of " + CHARS_PER_BYTE);
        }
        byte[] bytes = new byte[byteLen];
        for (int j = 0, a, b, c; i < len; bytes[j++] = (byte) (a * 100 + b * 10 + c)) {
            a = src.charAt(i++) - '0';
            b = src.charAt(i++) - '0';
            c = src.charAt(i++) - '0';
            if (a < 0 || a > 9 || b < 0 || b > 9 || c < 0 || c > 9) {
                throw new IllegalArgumentException("illegal digit");
            }
        }
        return bytes;
    }
}
