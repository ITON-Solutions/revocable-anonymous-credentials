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

import org.iton.jssi.ursa.pair.PointG1;
import org.iton.jssi.ursa.pair.PointG2;

import java.util.ArrayList;
import java.util.List;

public class NonRevocProofCList {
    public PointG1 e;
    public PointG1 d;
    public PointG1 a;
    public PointG1 g;
    public PointG2 w;
    public PointG2 s;
    public PointG2 u;

    public NonRevocProofCList(
            PointG1 e,
            PointG1 d,
            PointG1 a,
            PointG1 g,
            PointG2 w,
            PointG2 s,
            PointG2 u)
    {
        this.e = e;
        this.d = d;
        this.a = a;
        this.g = g;
        this.w = w;
        this.s = s;
        this.u = u;
    }

    public List<byte[]> toList() {
        List<byte[]> result = new ArrayList<>();
        result.add(e.toBytes());
        result.add(d.toBytes());
        result.add(a.toBytes());
        result.add(g.toBytes());
        result.add(w.toBytes());
        result.add(s.toBytes());
        result.add(u.toBytes());
        return result;
    }
}
