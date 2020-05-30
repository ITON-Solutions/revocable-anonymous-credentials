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

import org.iton.jssi.ursa.pair.GroupOrderElement;

import java.util.ArrayList;
import java.util.List;

public class NonRevocProofXList {
    public GroupOrderElement rho;
    public GroupOrderElement r;
    public GroupOrderElement r_prime;
    public GroupOrderElement r_prime_prime;
    public GroupOrderElement r_prime_prime_prime;
    public GroupOrderElement o;
    public GroupOrderElement o_prime;
    public GroupOrderElement m;
    public GroupOrderElement m_prime;
    public GroupOrderElement t;
    public GroupOrderElement t_prime;
    public GroupOrderElement m2;
    public GroupOrderElement s;
    public GroupOrderElement c;

    public NonRevocProofXList(
            GroupOrderElement rho,
            GroupOrderElement r,
            GroupOrderElement r_prime,
            GroupOrderElement r_prime_prime,
            GroupOrderElement r_prime_prime_prime,
            GroupOrderElement o,
            GroupOrderElement o_prime,
            GroupOrderElement m,
            GroupOrderElement m_prime,
            GroupOrderElement t,
            GroupOrderElement t_prime,
            GroupOrderElement m2,
            GroupOrderElement s,
            GroupOrderElement c)
    {
        this.rho = rho;
        this.r = r;
        this.r_prime = r_prime;
        this.r_prime_prime = r_prime_prime;
        this.r_prime_prime_prime = r_prime_prime_prime;
        this.o = o;
        this.o_prime = o_prime;
        this.m = m;
        this.m_prime = m_prime;
        this.t = t;
        this.t_prime = t_prime;
        this.m2 = m2;
        this.s = s;
        this.c = c;
    }

    public List<GroupOrderElement> toList()  {
        List<GroupOrderElement> result = new ArrayList<>();
        result.add(rho);
        result.add(o);
        result.add(c);
        result.add(o_prime);
        result.add(m);
        result.add(m_prime);
        result.add(t);
        result.add(t_prime);
        result.add(m2);
        result.add(s);
        result.add(r);
        result.add(r_prime);
        result.add(r_prime_prime);
        result.add(r_prime_prime_prime);
        return result;
    }

    public static NonRevocProofXList fromList(List<GroupOrderElement> seq) {
        return new NonRevocProofXList(
                seq.get(0),
                seq.get(10),
                seq.get(11),
                seq.get(12),
                seq.get(13),
                seq.get(1),
                seq.get(3),
                seq.get(4),
                seq.get(5),
                seq.get(6),
                seq.get(7),
                seq.get(8),
                seq.get(9),
                seq.get(2));
    }
}
