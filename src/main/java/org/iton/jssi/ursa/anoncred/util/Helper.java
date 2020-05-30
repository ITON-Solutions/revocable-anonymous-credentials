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

import org.iton.jssi.ursa.anoncred.CredentialPrimaryPublicKey;
import org.iton.jssi.ursa.anoncred.CredentialRevocationPublicKey;
import org.iton.jssi.ursa.anoncred.proof.NonRevocProofCList;
import org.iton.jssi.ursa.anoncred.proof.NonRevocProofTauList;
import org.iton.jssi.ursa.anoncred.proof.NonRevocProofXList;
import org.iton.jssi.ursa.pair.Pair;
import org.iton.jssi.ursa.pair.PointG1;
import org.iton.jssi.ursa.registry.RevocationPublicKey;
import org.iton.jssi.ursa.registry.RevocationRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.iton.jssi.ursa.anoncred.util.BigNumber.ITERATION;

public class Helper {

    private static final Logger LOG = LoggerFactory.getLogger(Helper.class);
    private static final BigInteger TWO_COMPL_REF = BigInteger.ONE.shiftLeft(64);

    public static byte[] hash(byte[] data){
        byte[] hash = new byte[0];

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(data);
        } catch (NoSuchAlgorithmException e){
            LOG.error(String.format("Error: %s", e.getMessage()));
        }
        return hash;
    }

    public static byte[] hash(List<byte[]> data){
        byte[] hash = new byte[0];

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for(byte[] bytes : data){
                digest.update(bytes);
            }
            hash = digest.digest();
        } catch (NoSuchAlgorithmException e){
            LOG.error(String.format("Error: %s", e.getMessage()));
        }
        return hash;
    }

    /// Generate a pedersen commitment to a given number
    ///
    /// # Arguments
    /// * `gen_1` - first generator
    /// * `m` - exponent of the first generator
    /// * `gen_2` - second generator
    /// * `r` - exponent of the second generator
    /// * `modulus` - all computations are done this modulo
    /// * `ctx` - big number context
    ///
    /// # Result
    /// Return the pedersen commitment, i.e `(gen_1^m)*(gen_2^r)`
    public static BigInteger getPedersenCommitment(
            BigInteger gen_1,
            BigInteger m,
            BigInteger gen_2,
            BigInteger r,
            BigInteger modulus)
    {
        BigInteger commitment = gen_1.modPow(m, modulus).multiply(gen_2.modPow(r, modulus)).mod(modulus);
        return commitment;
    }

    public static NonRevocProofTauList createTauListValues(
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            RevocationRegistry revocationRegistry,
            NonRevocProofXList nonRevocProofXList,
            NonRevocProofCList nonRevocProofCList) {


        PointG1 t1 = credentialRevocationPublicKey
                .h
                .mul(nonRevocProofXList.rho)
                .add(credentialRevocationPublicKey.h_tilde.mul(nonRevocProofXList.o));

        PointG1 t2 = nonRevocProofCList
                .e
                .mul(nonRevocProofXList.c)
                .add(credentialRevocationPublicKey.h.mul(nonRevocProofXList.m.modneg()))
                .add(credentialRevocationPublicKey.h_tilde.mul(nonRevocProofXList.t.modneg()));

        if (t2.isInfinity()) {
            t2 = new PointG1().infinity();
        }

        Pair t3 = Pair.pair(nonRevocProofCList.a, credentialRevocationPublicKey.h_cap)
                .pow(nonRevocProofXList.c)
                .mul(Pair.pair(credentialRevocationPublicKey.h_tilde, credentialRevocationPublicKey.h_cap).pow(nonRevocProofXList.r))
                .mul(Pair.pair(credentialRevocationPublicKey.h_tilde, credentialRevocationPublicKey.y)
                .pow(nonRevocProofXList.rho)
                .mul(Pair.pair(credentialRevocationPublicKey.h_tilde, credentialRevocationPublicKey.h_cap).pow(nonRevocProofXList.m))
                .mul(Pair.pair(credentialRevocationPublicKey.h1, credentialRevocationPublicKey.h_cap).pow(nonRevocProofXList.m2))
                .mul(Pair.pair(credentialRevocationPublicKey.h2, credentialRevocationPublicKey.h_cap).pow(nonRevocProofXList.s))
                .inverse());

        Pair t4 = Pair.pair(credentialRevocationPublicKey.h_tilde, revocationRegistry.accumulator)
                .pow(nonRevocProofXList.r)
                .mul(Pair.pair(credentialRevocationPublicKey.g.neg(), credentialRevocationPublicKey.h_cap).pow(nonRevocProofXList.r_prime));

        PointG1 t5 = credentialRevocationPublicKey
                .g
                .mul(nonRevocProofXList.r)
                .add(credentialRevocationPublicKey.h_tilde.mul(nonRevocProofXList.o_prime));

        PointG1 t6 = nonRevocProofCList
                .d
                .mul(nonRevocProofXList.r_prime_prime)
                .add(credentialRevocationPublicKey.g.mul(nonRevocProofXList.m_prime.modneg()))
                .add(credentialRevocationPublicKey.h_tilde.mul(nonRevocProofXList.t_prime.modneg()));

        if (t6.isInfinity()) {
                t6 = new PointG1().infinity();
        }

        Pair t7 = Pair.pair(credentialRevocationPublicKey.pk.add(nonRevocProofCList.g), credentialRevocationPublicKey.h_cap)
                .pow(nonRevocProofXList.r_prime_prime)
                .mul(Pair.pair(credentialRevocationPublicKey.h_tilde, credentialRevocationPublicKey.h_cap).pow(nonRevocProofXList.m_prime.modneg()))
                .mul(Pair.pair(credentialRevocationPublicKey.h_tilde, nonRevocProofCList.s).pow(nonRevocProofXList.r));

        Pair t8 = Pair.pair(credentialRevocationPublicKey.h_tilde, credentialRevocationPublicKey.u)
                .pow(nonRevocProofXList.r)
                .mul(Pair.pair(credentialRevocationPublicKey.g.neg(), credentialRevocationPublicKey.h_cap).pow(nonRevocProofXList.r_prime_prime_prime));

        return new  NonRevocProofTauList(t1, t2, t3, t4, t5, t6, t7, t8);
    }

    public static NonRevocProofTauList createTauListExpectedValues(
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            RevocationRegistry revocationRegistry,
            RevocationPublicKey revocationPublicKey,
            NonRevocProofCList nonRevocProofCList)
    {

        PointG1 t1 = nonRevocProofCList.e;
        PointG1 t2 = new PointG1().infinity();
        Pair t3 = Pair.pair(credentialRevocationPublicKey.h0.add(nonRevocProofCList.g), credentialRevocationPublicKey.h_cap)
                .mul(Pair.pair(nonRevocProofCList.a, credentialRevocationPublicKey.y).inverse());
        Pair t4 = Pair.pair(nonRevocProofCList.g, revocationRegistry.accumulator)
                .mul(Pair.pair(credentialRevocationPublicKey.g, nonRevocProofCList.w)
                .mul(revocationPublicKey.z)
                .inverse());
        PointG1 t5 = nonRevocProofCList.d;
        PointG1 t6 = new PointG1().infinity();
        Pair t7 = Pair.pair(credentialRevocationPublicKey.pk.add(nonRevocProofCList.g), nonRevocProofCList.s)
                .mul(Pair.pair(credentialRevocationPublicKey.g, credentialRevocationPublicKey.g_dash).inverse());
        Pair t8 = Pair.pair(nonRevocProofCList.g, credentialRevocationPublicKey.u)
                .mul(Pair.pair(credentialRevocationPublicKey.g, nonRevocProofCList.u).inverse());

        return new NonRevocProofTauList(t1, t2, t3, t4, t5, t6, t7, t8);
    }

    public static BigInteger calc_teq(
            CredentialPrimaryPublicKey p_pub_key,
            BigInteger a_prime,
            BigInteger e,
            BigInteger v,
            Map<String, BigInteger> m_tilde,
            BigInteger m2_tilde,
            List<String> unrevealed_attrs)
    {
        // a_prime^e % p_pub_key.n
        BigInteger result = a_prime.modPow(e, p_pub_key.n);
        for(String key : unrevealed_attrs){
            BigInteger cur_r = p_pub_key.r.get(key);
            if(cur_r == null){
                LOG.error(String.format("Value by key '%s' not found in pk.r", key));
                return null;
            }

            BigInteger cur_m = m_tilde.get(key);
            if(cur_m == null){
                LOG.error(String.format("Value by key '%s' not found in m_tilde", key));
                return null;
            }

            // result = result * (cur_r^cur_m % p_pub_key.n) % p_pub_key.n
            result = cur_r
                    .modPow(cur_m, p_pub_key.n)
                    .multiply(result)
                    .mod(p_pub_key.n);
        }

        result = p_pub_key
                .s
                .modPow(v, p_pub_key.n)
                .multiply(result)
                .mod(p_pub_key.n);

        result = p_pub_key
                .rctxt
                .modPow(m2_tilde, p_pub_key.n)
                .multiply(result)
                .mod(p_pub_key.n);


        return result;
    }

    public static List<BigInteger> calc_tne(
            CredentialPrimaryPublicKey p_pub_key,
            Map<String, BigInteger> u,
            Map<String, BigInteger> r,
            BigInteger mj,
            BigInteger alpha,
            Map<String, BigInteger> t,
            boolean isLess)
    {


        List<BigInteger> tau_list = new ArrayList<>();

        for(int i = 0; i < ITERATION; i++) {
            BigInteger cur_u = u.get(String.valueOf(i));
            if (cur_u == null) {
                LOG.error(String.format("Value by key '%d' not found in u", i));
                return null;
            }

            BigInteger cur_r = r.get(String.valueOf(i));
            if (cur_r == null) {
                LOG.error(String.format("Value by key '%d' not found in r", i));
                return null;
            }

            BigInteger t_tau = p_pub_key
                    .z
                    .modPow(cur_u, p_pub_key.n)
                    .multiply(p_pub_key.s.modPow(cur_r, p_pub_key.n))
                    .mod(p_pub_key.n);

            tau_list.add(t_tau);
        }

        BigInteger delta = r.get("DELTA");
        if (delta == null) {
            LOG.error(String.format("Value by key '%s' not found in r", "DELTA"));
            return null;
        }

        BigInteger delta_predicate = isLess ? delta.negate() : delta;

        BigInteger t_tau = p_pub_key
                .z
                .modPow(mj, p_pub_key.n)
                .multiply(p_pub_key.s.modPow(delta_predicate, p_pub_key.n))
                .mod(p_pub_key.n);

        tau_list.add(t_tau);

        BigInteger q = BigInteger.ONE;

        for(int i = 0; i < ITERATION; i ++) {
            BigInteger cur_t = t.get(String.valueOf(i));
            if (cur_t == null) {
                LOG.error(String.format("Value by key '%d' not found in t", i));
                return null;
            }

            BigInteger cur_u = u.get(String.valueOf(i));
            if (cur_u == null) {
                LOG.error(String.format("Value by key '%d' not found in u", i));
                return null;
            }

            q = cur_t.modPow(cur_u, p_pub_key.n).multiply(q);
        }

        q = p_pub_key
                .s
                .modPow(alpha, p_pub_key.n)
                .multiply(q)
                .mod(p_pub_key.n);

        tau_list.add(q);
        return tau_list;
    }
}
