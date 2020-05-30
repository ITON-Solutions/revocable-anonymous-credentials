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

package org.iton.jssi.ursa.anoncred.proof;

import org.iton.jssi.ursa.pair.Pair;
import org.iton.jssi.ursa.pair.PointG1;

import java.util.ArrayList;
import java.util.List;

public class NonRevocProofTauList {
    public PointG1 t1;
    public PointG1 t2;
    public Pair t3;
    public Pair t4;
    public PointG1 t5;
    public PointG1 t6;
    public Pair t7;
    public Pair t8;

    public NonRevocProofTauList(
            PointG1 t1,
            PointG1 t2,
            Pair t3,
            Pair t4,
            PointG1 t5,
            PointG1 t6,
            Pair t7,
            Pair t8)
    {
        this.t1 = t1;
        this.t2 = t2;
        this.t3 = t3;
        this.t4 = t4;
        this.t5 = t5;
        this.t6 = t6;
        this.t7 = t7;
        this.t8 = t8;
    }

    public List<byte[]> toList() {
        List<byte[]> result = new ArrayList<>();
        result.add(t1.toBytes());
        result.add(t2.toBytes());
        result.add(t3.toBytes());
        result.add(t4.toBytes());
        result.add(t5.toBytes());
        result.add(t6.toBytes());
        result.add(t7.toBytes());
        result.add(t8.toBytes());
        return result;
    }
}
