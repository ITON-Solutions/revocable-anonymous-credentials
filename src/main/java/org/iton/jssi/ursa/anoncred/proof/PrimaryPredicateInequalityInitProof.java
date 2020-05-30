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

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

public class PrimaryPredicateInequalityInitProof {

    List<BigInteger> c_list;
    List<BigInteger>  tau_list;
    Map<String, BigInteger> u;
    Map<String, BigInteger> u_tilde;
    Map<String, BigInteger> r;
    Map<String, BigInteger> r_tilde;
    BigInteger alpha_tilde;
    Predicate predicate;
    Map<String, BigInteger> t;

    public PrimaryPredicateInequalityInitProof(
            List<BigInteger> c_list,
            List<BigInteger>  tau_list,
            Map<String, BigInteger> u,
            Map<String, BigInteger> u_tilde,
            Map<String, BigInteger> r,
            Map<String, BigInteger> r_tilde,
            BigInteger alpha_tilde,
            Predicate predicate,
            Map<String, BigInteger> t)
    {
        this.c_list = c_list;
        this.tau_list = tau_list;
        this.u = u;
        this.u_tilde = u_tilde;
        this.r = r;
        this.r_tilde = r_tilde;
        this.alpha_tilde = alpha_tilde;
        this.predicate = predicate;
        this.t = t;
    }

    public List<BigInteger> toList() {
        return c_list;
    }

    public List<BigInteger> toTauList()  {
        return tau_list;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PrimaryPredicateInequalityInitProof that = (PrimaryPredicateInequalityInitProof) o;

        if (!c_list.equals(that.c_list)) return false;
        if (!tau_list.equals(that.tau_list)) return false;
        if (!u.equals(that.u)) return false;
        if (!u_tilde.equals(that.u_tilde)) return false;
        if (!r.equals(that.r)) return false;
        if (!r_tilde.equals(that.r_tilde)) return false;
        if (!alpha_tilde.equals(that.alpha_tilde)) return false;
        if (!predicate.equals(that.predicate)) return false;
        return t.equals(that.t);
    }
}
