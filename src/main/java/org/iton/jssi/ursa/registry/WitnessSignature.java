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

import org.iton.jssi.ursa.anoncred.CredentialRevocationPublicKey;
import org.iton.jssi.ursa.anoncred.NonRevocationCredentialSignature;
import org.iton.jssi.ursa.pair.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

public class WitnessSignature {

    private static final Logger LOG = LoggerFactory.getLogger(WitnessSignature.class);

    public PointG2 sigma_i;
    public PointG2 u_i;
    public PointG1 g_i;

    public WitnessSignature(PointG2 sigma_i, PointG2 u_i, PointG1 g_i){
        this.sigma_i = sigma_i;
        this.u_i = u_i;
        this.g_i = g_i;
    }

    public static boolean check(
            NonRevocationCredentialSignature nonRevocationCredentialSignature,
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            RevocationPublicKey revocationPublicKey,
            RevocationRegistry revocationRegistry,
            Witness witness,
            BigInteger r_cnxt_m2) throws CryptoException
    {
        LOG.debug("Check Witness signature...");

        if(revocationPublicKey == null || revocationRegistry == null || witness == null){
            LOG.debug("Optional parameters NULL. Witness signature checked");
            return true;
        }

        Pair z_calc = Pair.pair(nonRevocationCredentialSignature.witness_signature.g_i, revocationRegistry.accumulator)
                .mul(Pair.pair(credentialRevocationPublicKey.g, witness.omega).inverse());

        if (!z_calc.equals(revocationPublicKey.z)) {
            LOG.error("Issuer is sending incorrect data");
            return false;
        }

        Pair pair_gg_calc = Pair.pair(
                credentialRevocationPublicKey.pk.add(nonRevocationCredentialSignature.g_i),
                nonRevocationCredentialSignature.witness_signature.sigma_i);

        Pair pair_gg = Pair.pair(credentialRevocationPublicKey.g, credentialRevocationPublicKey.g_dash);

        if (!pair_gg_calc.equals(pair_gg)) {
            LOG.error("Issuer is sending incorrect data");
            return false;
        }

        GroupOrderElement m2 = GroupOrderElement.fromBytes(asUnsignedByteArray(r_cnxt_m2));

        Pair pair_h1 = Pair.pair(
                nonRevocationCredentialSignature.sigma,
                credentialRevocationPublicKey
                        .y
                        .add(credentialRevocationPublicKey.h_cap.mul(nonRevocationCredentialSignature.c)));

        Pair pair_h2 = Pair.pair(
                credentialRevocationPublicKey
                        .h0
                        .add(credentialRevocationPublicKey.h1.mul(m2))
                        .add(credentialRevocationPublicKey.h2.mul(nonRevocationCredentialSignature.vr_prime_prime))
                        .add(nonRevocationCredentialSignature.g_i),
                credentialRevocationPublicKey.h_cap);

        if (!pair_h1.equals(pair_h2)) {
            LOG.error("Issuer is sending incorrect data");
            return false;
        }

        LOG.debug("Check Witness signature... OK");
        return true;
    }
}
