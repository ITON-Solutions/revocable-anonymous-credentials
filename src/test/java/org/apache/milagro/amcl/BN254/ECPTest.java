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

package org.apache.milagro.amcl.BN254;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ECPTest {

    String data = "1 03D433008A42E55FE3C6C4772D290EB3B0BF999F8281B4329E55033A32663625 1 0BDFD038889932B7C5CDD0BB846713710FBAB698201DFD4A380CDD1282E75060 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8";

    @Test
    void fromHex() {
        ECP ecp = ECP.fromHex(data);
        assertEquals(data, ecp.toHex());
    }

    @Test
    void toHex() {
        String hex1 = "1 03D433008A42E55FE3C6C4772D290EB3B0BF999F8281B4329E55033A32663625";
        FP fp1 = FP.fromHex(hex1);
        String hex2 = "1 0BDFD038889932B7C5CDD0BB846713710FBAB698201DFD4A380CDD1282E75060";
        FP fp2 = FP.fromHex(hex2);
        String hex3 = "1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8";
        FP fp3 = FP.fromHex(hex3);
        ECP ecp = new ECP(fp1, fp2, fp3);
        assertEquals(data, ecp.toHex());
    }
}