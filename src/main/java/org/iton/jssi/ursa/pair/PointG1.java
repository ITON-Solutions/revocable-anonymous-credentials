/*
 * The MIT License
 *
 * Copyright 2019 ITON Solutions.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.iton.jssi.ursa.pair;

import org.apache.milagro.amcl.BN254.*;

import static org.apache.milagro.amcl.BN254.BIG.NLEN;

/**
 *
 * @author ITON Solutions
 */
public class PointG1 {
    public static final int BYTES_REPR_SIZE = BIG.MODBYTES * 4;
    
    protected ECP point;
    
    public PointG1(){
        // generate random point from the group G1
        BIG point_x = new BIG(ROM.CURVE_Gx);
        BIG point_y = new BIG(ROM.CURVE_Gy);
        
        ECP gen_g1 = new ECP(point_x, point_y);
        point = PAIR.G1mul(gen_g1, RandomGenerator.random());
    }
    
    public PointG1(ECP point){
        this.point = point;
    }
        
    // Creates new infinity PointG1
    public PointG1 infinity(){
        ECP result = new ECP();
        result.inf();
        return new PointG1(result);
    }

    // Checks infinity
    public boolean isInfinity(){
        return point.is_infinity();
    }

    // PointG1 ^ GroupOrderElement
    public PointG1 mul(GroupOrderElement g){
        ECP result = PAIR.G1mul(point, g.big);
        return new PointG1(result);
    }

    // PointG1 * PointG1
    public  PointG1 add(PointG1 point){
        ECP result = new ECP(this.point);
        result.add(point.point);
        return new PointG1(result);
    }

    // PointG1 / PointG1
    public  PointG1 sub(PointG1 point){
        ECP result = new ECP(this.point);
        result.sub(point.point);
        return new PointG1(result);
    }

    // 1 / PointG1
    public  PointG1 neg(){
        ECP result = new ECP(point);
        result.neg();
        return new PointG1(result);
    }


    public byte[] toBytes(){
        byte[] result = new byte[BYTES_REPR_SIZE];
        point.toBytes(result, false);
        return result;
    }

    public PointG1 fromBytes(byte[] data) throws CryptoException {
        if (data.length != BYTES_REPR_SIZE) {
            throw new CryptoException("Invalid length of bytes representation");
        }

        ECP result = ECP.fromBytes(data);
        return new PointG1(result);
    }
    
    public PointG1 fromHash(byte[] hash) throws CryptoException {
        GroupOrderElement el = new GroupOrderElement().fromBytes(hash);
        ECP result = new ECP(el.big);

        while (result.is_infinity()) {
            el.big.inc(1);
            result = new ECP(el.big);
        }

        return new PointG1(result);
    }

    public static PointG1 fromHex(String hex){
        ECP ecp = ECP.fromHex(hex);
        return new PointG1(ecp);
    }

    public static PointG1 fromHex(String[] hex) throws CryptoException {

        if (hex.length != NLEN * 3) {
            throw new CryptoException(String.format("Invalid array length: %d (must be %d", hex.length, NLEN * 6));
        }

        long[] longs = new long[NLEN];
        BIG[] bigs = new BIG[hex.length / NLEN];

        for (int i = 0; i < hex.length / NLEN; i++) {
            longs[0] = Long.parseLong(hex[NLEN * i], 16);
            longs[1] = Long.parseLong(hex[NLEN * i + 1], 16);
            longs[2] = Long.parseLong(hex[NLEN * i + 2], 16);
            longs[3] = Long.parseLong(hex[NLEN * i + 3], 16);
            longs[4] = Long.parseLong(hex[NLEN * i + 4], 16);
            bigs[i] = new BIG(longs);
        }

        ECP ecp = new ECP(new FP(bigs[0]), new FP(bigs[1]), new FP(bigs[2]));
        return new PointG1(ecp);
    }

    public String toHex() {
        return point.toHex();
    }
}
