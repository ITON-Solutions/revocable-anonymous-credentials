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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PointG1Test {

    @Test
    void fromHex() {
        String data = "1 03D433008A42E55FE3C6C4772D290EB3B0BF999F8281B4329E55033A32663625 1 0BDFD038889932B7C5CDD0BB846713710FBAB698201DFD4A380CDD1282E75060 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8";
        PointG1 point = PointG1.fromHex(data);
        assertEquals(data, point.toHex());
    }

    @Test
    void fromArray(){
        String data = "61FEBE2CFEAA04 5440090222C6AC E933B40264261C A5AA97421F4AEB 1D18E69F 23DDFBC92248BC F4CD0C7051CBEC 7057318CAFB551 B88E41A2CB508A 1461756F FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD";
        try {
            PointG1 pointG1 = PointG1.fromHex(data.split(" "));

            String x = pointG1.point.getx().redc().toHex();
            String y = pointG1.point.gety().redc().toHex();
            String z = pointG1.point.getz().redc().toHex();

            StringBuffer buffer = new StringBuffer()
                    .append(x).append(" ")
                    .append(y).append(" ")
                    .append(z);

            assertEquals(buffer.toString(), data);
        } catch (CryptoException e){
            assertTrue(false, e.getMessage());
        }
    }

}