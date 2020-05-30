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
import org.apache.milagro.amcl.BN254.ROM;
import org.apache.milagro.amcl.RAND;
import org.iton.jssi.ursa.util.Bytes;

import static org.apache.milagro.amcl.BN254.BIG.NLEN;

/**
 *
 * @author ITON Solutions
 */
public class GroupOrderElement {
    
    public static final int BYTES_REPR_SIZE = BIG.MODBYTES;
    
    protected BIG big;
    
    public GroupOrderElement(){
        big = RandomGenerator.random();
    }
    
    public GroupOrderElement(BIG big){
        this.big = big;
    }
    
    public GroupOrderElement fromSeed(byte[] seed) throws CryptoException{
        // returns random element in 0, ..., GroupOrder-1
        if (seed.length != BIG.MODBYTES) {
            throw new CryptoException(String.format("Invalid len of seed: expected %d, actual &d", BIG.MODBYTES, seed.length));
        }
        RAND rand = new RAND();
        rand.clean();
        rand.seed(seed.length, seed);

        BIG result = BIG.randomnum(new BIG(ROM.CURVE_Order), rand);
        return new GroupOrderElement(result);
    }
    
    public byte[] toBytes() {
        byte[] result = new byte[BYTES_REPR_SIZE];
        big.toBytes(result);
        return result;
    }

    public String toHex() {
        return big.toHex();
    }

    public static GroupOrderElement fromHex(String hex) throws CryptoException {
        byte[] bytes = Bytes.toBytes(hex);
        return fromBytes(bytes);
    }

    public static GroupOrderElement fromHex(String[] hex) throws CryptoException {

        if(hex.length != NLEN){
            throw new CryptoException(String.format("Invalid array length: %d (must be %d", hex.length, NLEN));
        }

        BIG big = BIG.fromHex(hex);
        return new GroupOrderElement(big);
    }
    
    public static GroupOrderElement fromBytes(byte[] data) throws CryptoException {
        if (data.length > BYTES_REPR_SIZE) {
            throw new CryptoException("Invalid length of bytes representation");
        }
        
        int length = data.length;
        if (length < BIG.MODBYTES) {
            byte[] diff = new byte[BIG.MODBYTES - length];
            byte[] conc = Bytes.concat(diff, data);
            
            BIG result = BIG.fromBytes(conc);
            return new GroupOrderElement(result);
        }
        
        BIG result = BIG.fromBytes(data);
        return new GroupOrderElement(result);
    }
    
    public GroupOrderElement mulmod(GroupOrderElement g){
        BIG result = BIG.modmul(big, g.big, new BIG(ROM.CURVE_Order));
        return new GroupOrderElement(result);
    }

    /// 1 / GroupOrderElement
    public GroupOrderElement inverse() {
        BIG result = new BIG(big);
        result.invmodp(new BIG(ROM.CURVE_Order));
        return new GroupOrderElement(result);
    }

    /// - GroupOrderElement mod GroupOrder
    public GroupOrderElement modneg() {
        BIG result = new BIG(big);
        result = BIG.modneg(result, new BIG(ROM.CURVE_Order));
        return new GroupOrderElement(result);
    }

    public GroupOrderElement powmod(GroupOrderElement e) {
        BIG base = this.big;
        BIG pow = e.big;
        BIG result = base.powmod(pow, new BIG(ROM.CURVE_Order));
        return new GroupOrderElement(result);
    }

    /// (GroupOrderElement + GroupOrderElement) mod GroupOrder
    public GroupOrderElement addmod(GroupOrderElement r) {
        BIG result = new BIG(big);
        result.add(r.big);
        result.mod(new BIG(ROM.CURVE_Order));
        return new GroupOrderElement(result);
    }
}
