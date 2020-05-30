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

package org.iton.jssi.ursa.anoncred.util;

import org.iton.jssi.ursa.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class BigNumber {

    private static final Logger LOG = LoggerFactory.getLogger(BigNumber.class);

    public static final int CERTAINTY = 100; // BigInteger also uses 100 for its default certainty
    public static final int LARGE_MASTER_SECRET = 256;

    public static final int LARGE_E_START = 596;
    public static final int LARGE_E_END_RANGE = 119;

    public static final int LARGE_PRIME = 1024;
    public static final int LARGE_VPRIME = 2128;
    public static final int LARGE_VPRIME_PRIME = 2724;
    public static final int LARGE_MVECT = 592;
    public static final int LARGE_ETILDE = 456;
    public static final int LARGE_VTILDE = 3060;
    public static final int LARGE_UTILDE = 592;
    public static final int LARGE_MTILDE = 593;
    public static final int LARGE_VPRIME_TILDE = 673;
    public static final int LARGE_RTILDE = 672;
    public static final int LARGE_ALPHATILDE = 2787;
    public static final int ITERATION = 4;
    public static BigInteger TWO = BigInteger.valueOf(2);

    public static final BigInteger LARGE_E_START_VALUE = TWO.pow(LARGE_E_START);
    public static final BigInteger LARGE_E_END_RANGE_VALUE = TWO.pow(LARGE_E_END_RANGE).add(LARGE_E_START_VALUE);
    public static final BigInteger LARGE_VPRIME_PRIME_VALUE = TWO.pow(LARGE_VPRIME_PRIME - 1);

    public static final int LARGE_NONCE = 80; // number of bits

    private static final int MAX_ITERATIONS = 100;

    public enum ByteOrder {
        BIG,
        LITTLE,
    }

    public static BigInteger prime(int size){
        return BigInteger.probablePrime(size, new SecureRandom());
    }

    public static BigInteger primeInRange(BigInteger start, BigInteger end){

        int cmp = start.compareTo(end);
        if (cmp > 0) {
            throw new IllegalArgumentException("'min' may not be greater than 'max'");
        }

        BigInteger result = randomInRange(start, end, new SecureRandom());

        while(!result.isProbablePrime(100)){
            result = randomInRange(start, end, new SecureRandom());
        }
        return result;
    }

    /**
     * Return a random BigInteger not less than 'min' and not greater than 'max'
     *
     * @param min the least value that may be generated
     * @param max the greatest value that may be generated
     * @param random the source of randomness
     * @return a random BigInteger value in the range [min, max]
     */
    public static BigInteger randomInRange(BigInteger min, BigInteger max, SecureRandom random) {
        int cmp = min.compareTo(max);
        if (cmp >= 0) {
            if (cmp > 0) {
                throw new IllegalArgumentException("'min' may not be greater than 'max'");
            }
            return min;
        }

        if (min.bitLength() > max.bitLength() / 2) {
            return randomInRange(BigInteger.ZERO, max.subtract(min), random).add(min);
        }

        for (int i = 0; i < MAX_ITERATIONS; ++i) {
            BigInteger result = new BigInteger(max.bitLength(), random);
            if (result.compareTo(min) >= 0 && result.compareTo(max) <= 0) {
                return result;
            }
        }
        // fall back to a faster (restricted) method
        return new BigInteger(max.subtract(min).bitLength() - 1, random).add(min);
    }

    public static BigInteger randomQr(BigInteger data){
        BigInteger result = randomInRange(BigInteger.ZERO, data, new SecureRandom());
        return result.multiply(result).mod(data);
    }

    // Express the natural number `delta` as a sum of four integer squares,
    // i.e `delta = a^2 + b^2 + c^2 + d^2` using Lagrange's four-square theorem
    public static Map<String, BigInteger> lagrange(int delta){
        int[] roots = new int[]{(int) Math.sqrt(delta), 0, 0, 0};

        int sum = 0;
        outer:
        for(int i = roots[0]; i > 0; i--){
            roots[0] = i;
            sum = i * i;
            if(delta == sum){
                roots[1] = 0;
                roots[2] = 0;
                roots[3] = 0;
                break outer;
            }

            roots[1] = (int) Math.sqrt(delta - sum);
            for(int j = roots[1]; j > 0; j--){
                roots[1] = j;
                sum = i * i + j * j;
                if(delta == sum) {
                    roots[2] = 0;
                    roots[3] = 0;
                    break outer;
                }

                roots[2] = (int) Math.sqrt(delta - sum);
                for(int k = roots[2]; k > 0; k--)  {
                    roots[2] = k;
                    sum = i * i + j * j + k * k;
                    if(delta == sum) {
                        roots[3] = 0;
                        break outer;
                    }

                    roots[3] = (int) Math.sqrt(delta - sum);
                    if(delta == sum + roots[3] * roots[3]) {
                        break outer;
                    }
                }
            }
        }

        Map<String, BigInteger> result = new HashMap<>();
        result.put(String.valueOf(0), BigInteger.valueOf(roots[0]));
        result.put(String.valueOf(1), BigInteger.valueOf(roots[1]));
        result.put(String.valueOf(2), BigInteger.valueOf(roots[2]));
        result.put(String.valueOf(3), BigInteger.valueOf(roots[3]));
        return result;
    }

    public static BigInteger encodeAttribute(String attr, ByteOrder order){

        byte[] hash = Helper.hash(attr.getBytes());

        if(order == ByteOrder.LITTLE){
            hash = Bytes.reverse(hash);
        }
        return new BigInteger(1, hash);
    }

    // random number rng in interval [2, p*q - 1]
    public static BigInteger genX(BigInteger p, BigInteger q){
        BigInteger x = p.multiply(q).subtract(BigInteger.ONE);
        return randomInRange(TWO, x, new SecureRandom());
    }

    public static BigInteger modPow(BigInteger a,BigInteger exp, BigInteger m){
        if(m.signum() <= 0){
            m = m.negate();
        }
        return a.modPow(exp, m);
    }

    public static boolean isSafePrime(BigInteger b){
        return b.shiftLeft(1).add(BigInteger.ONE).isProbablePrime(100);
    }

    /**
     * Creates a safe prime number of the given bit length. A prime number <code>p</code> is safe, if p=2*q+1, where q
     * is also prime. Certainty a measure of the uncertainty that the caller is  willing to tolerate: if the call returns {@code true}
     * the probability that this BigInteger is prime exceeds (1 - 1/2<sup>{@code certainty}</sup>).  The execution time of
     * this method is proportional to the value of this parameter.
     * @param bitLength the length of the prime number
     * @param random    the random pool used
     * @return java.math.BigInteger which is a safe prime number
     */
    public static BigInteger safePrime(int bitLength, SecureRandom random) {
        BigInteger p, q;
        int qLength = bitLength - 1;

        do {
            q = BigInteger.probablePrime(qLength, random);
            // p <- 2q + 1
            p = q.shiftLeft(1).add(BigInteger.ONE);
        } while(!p.isProbablePrime(CERTAINTY));

        return p;

//        q = BigInteger.probablePrime(qLength, random);
//        p = q.add(q).add(BigInteger.ONE);
//
//        while (!p.isProbablePrime(CERTAINTY)) {
//            do {
//                q = q.nextProbablePrime();
//
//            } while (q.mod(BigInteger.TEN).equals(BigInteger.valueOf(7))
//                    || !q.remainder(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3)));
//
//            p = q.add(q).add(BigInteger.ONE);
//
//            while (p.bitLength() != bitLength) {
//                q = BigInteger.probablePrime(qLength, random);
//                p = q.add(q).add(BigInteger.ONE);
//            }
//        }
//        return p;
    }

    public static BigInteger random(int size){
        BigInteger min = TWO.pow(size - 1);
        BigInteger max = min.multiply(TWO).subtract(BigInteger.ONE);
        return randomInRange(min, max, new SecureRandom());
    }

    public static BigInteger getVPrimePrime()  {
        BigInteger a = random(LARGE_VPRIME_PRIME);
        return a.or(LARGE_VPRIME_PRIME_VALUE);
    }
}
