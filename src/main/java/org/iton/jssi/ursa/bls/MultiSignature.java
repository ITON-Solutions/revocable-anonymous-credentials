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
package org.iton.jssi.ursa.bls;

import org.iton.jssi.ursa.pair.CryptoException;
import org.iton.jssi.ursa.pair.PointG1;

/**
 *
 * @author ITON Solutions
 */
public class MultiSignature {
    PointG1 point;
    byte[] bytes;
    
    public MultiSignature(){}
    
    public MultiSignature(PointG1 point){
        this.point = point;
        bytes = point.toBytes();
    }
    
    public MultiSignature(Signature[] signatures){
        
        point = new PointG1().infinity();
        
        for(Signature signature : signatures){
            point = point.add(signature.point);
        }
        
        bytes = point.toBytes();
    }
    
    public byte[] toBytes(){
        return bytes;
    }
    
    public MultiSignature fromBytes(byte[] bytes) throws CryptoException {
        PointG1 result = new PointG1().fromBytes(bytes);
        return new MultiSignature(result);
    }
}
