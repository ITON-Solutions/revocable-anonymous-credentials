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

package org.iton.jssi.ursa.pair;

import org.iton.jssi.ursa.util.Bytes;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GroupOrderElementTest {

    @Test
    void fromBytes() throws CryptoException {
        byte[] vec = new byte[]{
                (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
                (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
                (byte) 116, (byte) 221, (byte) 243, (byte) 243, (byte) 0, (byte) 77, (byte) 170, (byte) 65,
                (byte) 179, (byte) 245, (byte) 119, (byte) 182, (byte) 251, (byte) 185, (byte) 78, (byte) 98};

        GroupOrderElement bytes = GroupOrderElement.fromBytes(vec);
        byte[] result = bytes.toBytes();
        assertArrayEquals(vec, result);
    }

    @Test
    void toBytes() throws CryptoException {
        GroupOrderElement goe = new GroupOrderElement();
        byte[] bytes = goe.toBytes();
        byte[] result =  GroupOrderElement.fromHex(Bytes.toHex(bytes)).toBytes();
        assertArrayEquals(bytes, result);
    }

    @Test
    void toHex(){
        String data = "9A7934671787E7 B44902FD431283 E541AB2729B4F7 E4BDDF7F08FE77 19ADFD0";
        try {
            GroupOrderElement goe = GroupOrderElement.fromHex(data.split(" "));
            assertEquals(goe.toHex(), data);
            assertEquals(goe.toBytes().length, GroupOrderElement.BYTES_REPR_SIZE);
        } catch (CryptoException e){
            assertTrue(false, e.getMessage());
        }
    }

    @Test
    void inverse() throws CryptoException {
        GroupOrderElement goe = new GroupOrderElement();
        GroupOrderElement inverse = goe.inverse();
        GroupOrderElement result = inverse.inverse();
        assertArrayEquals(goe.toBytes(), result.toBytes());
    }

    @Test
    void modneg() {
        GroupOrderElement goe = new GroupOrderElement();
        GroupOrderElement modneg = goe.modneg();
        GroupOrderElement result = modneg.modneg();
        assertArrayEquals(goe.toBytes(), result.toBytes());
    }
}