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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

public class PrimaryEqualInitProof {

    public BigInteger a_prime;
    public BigInteger t;
    public BigInteger e_tilde;
    public BigInteger  e_prime;
    public BigInteger v_tilde;
    public BigInteger v_prime;
    public Map<String, BigInteger > m_tilde;
    public BigInteger m2_tilde;
    public BigInteger m2;

    public PrimaryEqualInitProof(
            BigInteger a_prime,
            BigInteger t,
            BigInteger e_tilde,
            BigInteger e_prime,
            BigInteger v_tilde,
            BigInteger v_prime,
            Map<String, BigInteger> m_tilde,
            BigInteger m2_tilde,
            BigInteger m2)
    {
        this.a_prime = a_prime;
        this.t = t;
        this.e_tilde = e_tilde;
        this.e_prime = e_prime;
        this.v_tilde = v_tilde;
        this.v_prime = v_prime;
        this.m_tilde = m_tilde;
        this.m2_tilde = m2_tilde;
        this.m2 = m2;
    }

    public List<byte[]> toList() {
        List<byte[]> result = new ArrayList<>();
        result.add(asUnsignedByteArray(a_prime));
        return result;
    }

    public List<byte[]> toTauList() {
        List<byte[]> result = new ArrayList<>();
        result.add(asUnsignedByteArray(t));
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PrimaryEqualInitProof that = (PrimaryEqualInitProof) o;

        if (!a_prime.equals(that.a_prime)) return false;
        if (!t.equals(that.t)) return false;
        if (!e_tilde.equals(that.e_tilde)) return false;
        if (!e_prime.equals(that.e_prime)) return false;
        if (!v_tilde.equals(that.v_tilde)) return false;
        if (!v_prime.equals(that.v_prime)) return false;
        if (!m_tilde.equals(that.m_tilde)) return false;
        if (!m2_tilde.equals(that.m2_tilde)) return false;
        return m2.equals(that.m2);
    }
}
