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

package org.iton.jssi.ursa.registry;

import org.iton.jssi.ursa.pair.CryptoException;
import org.iton.jssi.ursa.pair.GroupOrderElement;
import org.iton.jssi.ursa.pair.PointG2;
import org.iton.jssi.ursa.rlp.util.Integers;

public class Tail extends PointG2{

    public Tail(PointG2 pointG2) {
        super(pointG2);
    }

    public Tail(){
        super();
    }

    public static Tail create(int index, PointG2 g_dash, GroupOrderElement gamma) {
        byte[] i_bytes = Integers.toBytes(index);
        try {
            GroupOrderElement pow = new GroupOrderElement().fromBytes(i_bytes);
            pow = gamma.powmod(pow);
            return new Tail(g_dash.mul(pow));
        } catch (CryptoException e){
            return new Tail();
        }
    }
}
