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

import org.apache.milagro.amcl.BN254.BIG;
import org.apache.milagro.amcl.BN254.ECP2;
import org.apache.milagro.amcl.BN254.FP2;
import org.apache.milagro.amcl.BN254.PAIR;
import org.apache.milagro.amcl.BN254.ROM;

import static org.apache.milagro.amcl.BN254.BIG.NLEN;

/**
 *
 * @author ITON Solutions
 */
public class PointG2 {
    
    public static final int BYTES_REPR_SIZE = BIG.MODBYTES * 4;
    
    protected ECP2 point;
    
    public PointG2(){
        // generate random point from the group G2
        BIG point_xa = new BIG(ROM.CURVE_Pxa);
        BIG point_xb = new BIG(ROM.CURVE_Pxb);
        
        BIG point_ya = new BIG(ROM.CURVE_Pya);
        BIG point_yb = new BIG(ROM.CURVE_Pyb);
        
        FP2 point_x = new FP2(point_xa, point_xb);
        FP2 point_y = new FP2(point_ya, point_yb);
        
        ECP2 gen_g1 = new ECP2(point_x, point_y);
        point = PAIR.G2mul(gen_g1, RandomGenerator.random());
    }

    public PointG2(PointG2 pointG2){
        this.point = pointG2.point;
    }

    public PointG2(ECP2 point){
        this.point = point;
    }
    
    // Creates new infinity PointG2
    public static PointG2 infinity(){
        ECP2 result = new ECP2();
        result.inf();
        return new PointG2(result);
    }

    // Checks infinity
    public boolean isInfinity(){
        return point.is_infinity();
    }
    
    // PointG2 * PointG2
    public  PointG2 add(PointG2 point){
        ECP2 result = new ECP2(this.point);
        result.add(point.point);
        return new PointG2(result);
    }
    
    // PointG2 / PointG2
    public  PointG2 sub(PointG2 point){
        ECP2 result = new ECP2(this.point);
        result.sub(point.point);
        return new PointG2(result);
    }
    
    // PointG2 ^ GroupOrderElement
    public PointG2 mul(GroupOrderElement g){
        ECP2 result = PAIR.G2mul(point, g.big);
        return new PointG2(result);
    }

    public static PointG2 fromHex(String hex){
        ECP2 ecp = ECP2.fromHex(hex);
        return new PointG2(ecp);
    }

    public static PointG2 fromHex(String[] hex) throws CryptoException {

        if(hex.length != NLEN * 6){
            throw new CryptoException(String.format("Invalid array length: %d (must be %d", hex.length, NLEN * 6));
        }

        long[] longs = new long[NLEN];
        BIG[] bigs = new BIG[hex.length / NLEN];

        for(int i = 0; i < hex.length / NLEN; i++){
            longs[0] = Long.parseLong(hex[NLEN * i], 16);
            longs[1] = Long.parseLong(hex[NLEN * i + 1], 16);
            longs[2] = Long.parseLong(hex[NLEN * i + 2], 16);
            longs[3] = Long.parseLong(hex[NLEN * i + 3], 16);
            longs[4] = Long.parseLong(hex[NLEN * i + 4], 16);
            bigs[i] = new BIG(longs);
        }
        FP2[] fp2 = new FP2[bigs.length / 2];
        for(int i = 0; i < fp2.length; i++){
            fp2[i] = new FP2(bigs[2 * i], bigs[2 * i + 1]);
        }
        ECP2 ecp = new ECP2(fp2[0], fp2[1], fp2[2]);
        return new PointG2(ecp);
    }

    public String toHex() {
        return point.toHex();
    }
    
    public byte[] toBytes(){
        byte[] result = new byte[BYTES_REPR_SIZE];
        point.toBytes(result);
        return result;
    }
    
    public static PointG2 fromBytes(byte[] data) throws CryptoException {
        if (data.length != BYTES_REPR_SIZE) {
            throw new CryptoException("Invalid length of bytes representation");
        }

        ECP2 result = ECP2.fromBytes(data);
        return new PointG2(result);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PointG2 pointG2 = (PointG2) o;

        return point.equals(pointG2.point);
    }

}
