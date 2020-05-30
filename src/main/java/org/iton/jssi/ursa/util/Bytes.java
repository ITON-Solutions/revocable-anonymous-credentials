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

package org.iton.jssi.ursa.util;


import org.spongycastle.util.encoders.Hex;

import java.nio.ByteBuffer;

public class Bytes {

    /**
     * Returns {@code true} if {@code target} is present as an element anywhere in {@code array}.
     *
     * @param array an array of {@code byte} values, possibly empty
     * @param target a primitive {@code byte} value
     * @return {@code true} if {@code array[i] == target} for some value of {@code i}
     */
    public static boolean contains(byte[] array, byte target) {
        for (byte value : array) {
            if (value == target) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the index of the first appearance of the value {@code target} in {@code array}.
     *
     * @param array an array of {@code byte} values, possibly empty
     * @param target a primitive {@code byte} value
     * @return the least index {@code i} for which {@code array[i] == target}, or {@code -1} if no
     *     such index exists.
     */
    public static int indexOf(byte[] array, byte target) {
        return indexOf(array, target, 0, array.length);
    }

    private static int indexOf(byte[] array, byte target, int start, int end) {
        for (int i = start; i < end; i++) {
            if (array[i] == target) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Returns the start position of the first occurrence of the specified {@code target} within
     * {@code array}, or {@code -1} if there is no such occurrence.
     *
     * <p>More formally, returns the lowest index {@code i} such that {@code Arrays.copyOfRange(array,
     * i, i + target.length)} contains exactly the same elements as {@code target}.
     *
     * @param array the array to search for the sequence {@code target}
     * @param target the array to search for as a sub-sequence of {@code array}
     */
    public static int indexOf(byte[] array, byte[] target) {

        if (target.length == 0) {
            return 0;
        }

        outer:
        for (int i = 0; i < array.length - target.length + 1; i++) {
            for (int j = 0; j < target.length; j++) {
                if (array[i + j] != target[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * Returns the values from each provided array combined into a single array. For example, {@code
     * concat(new byte[] {a, b}, new byte[] {}, new byte[] {c}} returns the array {@code {a, b, c}}.
     *
     * @param arrays zero or more {@code byte} arrays
     * @return a single array containing all the values from the source arrays, in order
     */
    public static byte[] concat(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }

    public static String toHex(byte[] bytes) {
        return bytes == null ? "" : Hex.toHexString(bytes);
    }

    public static byte[] toBytes(String data) {
        byte[] result = new byte[data.length() / 2];

        for (int i = 0; i < result.length; i++) {
            int index = i * 2;
            result[i] = Integer.valueOf(data.substring(index, index + 2), 0x10).byteValue();
        }
        return result;
    }

    public static byte[] toBytes(int value) {
        byte[] result = new byte[4];
        result[0] = (byte) (value >> 24);
        result[1] = (byte) (value >> 16);
        result[2] = (byte) (value >> 8);
        result[3] = (byte) value;
        return result;
    }

    /**
     * Returns the array with byte b inserted in position index
     */
    public static byte[] put(byte[] array, byte b, int index) {
        byte[] result = new byte[array.length + 1];
        System.arraycopy(array, 0, result, 0, index);
        result[index] = b;
        System.arraycopy(array, index, result, index + 1, array.length);
        return result;
    }

    public static long toLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(bytes.length);
        buffer.put(bytes, 0, bytes.length);
        buffer.flip();//need flip
        return buffer.getLong();
    }

    public static byte[] reverse(byte[] a){
        if (a == null){
            return null;
        }

        int p1 = 0, p2 = a.length;
        byte[] result = new byte[p2];

        while (--p2 >= 0){
            result[p2] = a[p1++];
        }

        return result;
    }
}
