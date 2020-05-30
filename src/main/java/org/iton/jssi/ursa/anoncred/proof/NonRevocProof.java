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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.iton.jssi.ursa.anoncred.CredentialRevocationPublicKey;
import org.iton.jssi.ursa.anoncred.NonRevocationCredentialSignature;
import org.iton.jssi.ursa.anoncred.util.Helper;
import org.iton.jssi.ursa.pair.CryptoException;
import org.iton.jssi.ursa.pair.GroupOrderElement;
import org.iton.jssi.ursa.pair.PointG1;
import org.iton.jssi.ursa.pair.PointG2;
import org.iton.jssi.ursa.registry.RevocationRegistry;
import org.iton.jssi.ursa.registry.Witness;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

public class NonRevocProof {

    public NonRevocProofXList x_list;
    public NonRevocProofCList c_list;

    @JsonCreator
    private NonRevocProof(
            @JsonProperty("x_list") NonRevocProofXList x_list,
            @JsonProperty("c_list") NonRevocProofCList c_list)
    {
        this.x_list = x_list;
        this.c_list = c_list;
    }

    public static NonRevocInitProof init(
            NonRevocationCredentialSignature nonRevocationCredentialSignature,
            RevocationRegistry revocationRegistry,
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            Witness witness) throws CryptoException {

        NonRevocProofXList c_list_params = createCListParams(nonRevocationCredentialSignature);
        NonRevocProofCList c_list = createCListValues(
                nonRevocationCredentialSignature,
                c_list_params,
                credentialRevocationPublicKey,
                witness);

        NonRevocProofXList tau_list_params = createTauListParams();
        NonRevocProofTauList tau_list = Helper.createTauListValues(
                credentialRevocationPublicKey,
                revocationRegistry,
                tau_list_params,
                c_list);

        return new  NonRevocInitProof(c_list_params, tau_list_params, c_list, tau_list);
    }

    public static NonRevocProof finalize(
            NonRevocInitProof nonRevocInitProof,
            BigInteger c_h) throws CryptoException {

        GroupOrderElement ch_num_z = GroupOrderElement.fromBytes(asUnsignedByteArray(c_h));

        List<GroupOrderElement> x_list = new ArrayList<>();

        // Iterate over two list simultaneously
        Iterator<GroupOrderElement> tau_list_params_iterator = nonRevocInitProof.tau_list_params.toList().listIterator();
        Iterator<GroupOrderElement> c_list_params_iterator = nonRevocInitProof.c_list_params.toList().listIterator();
        while(tau_list_params_iterator.hasNext() && c_list_params_iterator.hasNext()){
            GroupOrderElement x = tau_list_params_iterator.next();
            GroupOrderElement y = c_list_params_iterator.next();
            x_list.add(x.addmod(ch_num_z.mulmod(y).modneg()));
        }

        return new  NonRevocProof(NonRevocProofXList.fromList(x_list), nonRevocInitProof.c_list);
    }

    private static NonRevocProofXList createCListParams(NonRevocationCredentialSignature r_cred) throws CryptoException {

        GroupOrderElement rho = new GroupOrderElement();
        GroupOrderElement r = new GroupOrderElement();
        GroupOrderElement r_prime = new GroupOrderElement();
        GroupOrderElement r_prime_prime = new GroupOrderElement();
        GroupOrderElement r_prime_prime_prime = new GroupOrderElement();
        GroupOrderElement o = new GroupOrderElement();
        GroupOrderElement o_prime = new GroupOrderElement();

        GroupOrderElement m = rho.mulmod(r_cred.c);
        GroupOrderElement m_prime = r.mulmod(r_prime_prime);
        GroupOrderElement t = o.mulmod(r_cred.c);
        GroupOrderElement t_prime = o_prime.mulmod(r_prime_prime);
        GroupOrderElement m2 = GroupOrderElement.fromBytes(r_cred.m2.toBytes());

        return new NonRevocProofXList(
                rho,
                r,
                r_prime,
                r_prime_prime,
                r_prime_prime_prime,
                o,
                o_prime,
                m,
                m_prime,
                t,
                t_prime,
                m2,
                r_cred.vr_prime_prime,
                r_cred.c);
    }

    private static NonRevocProofCList createCListValues(
            NonRevocationCredentialSignature nonRevocationCredentialSignature,
            NonRevocProofXList nonRevocProofXList,
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            Witness witness)
    {

        PointG1 e = credentialRevocationPublicKey
                .h
                .mul(nonRevocProofXList.rho)
                .add(credentialRevocationPublicKey.h_tilde.mul(nonRevocProofXList.o));

        PointG1 d = credentialRevocationPublicKey
                .g
                .mul(nonRevocProofXList.r)
                .add(credentialRevocationPublicKey.h_tilde.mul(nonRevocProofXList.o_prime));

        PointG1 a = nonRevocationCredentialSignature
                .sigma
                .add(credentialRevocationPublicKey.h_tilde.mul(nonRevocProofXList.rho));
        PointG1 g = nonRevocationCredentialSignature
                .g_i
                .add(credentialRevocationPublicKey.h_tilde.mul(nonRevocProofXList.r));
        PointG2 w = witness
                .omega
                .add(credentialRevocationPublicKey.h_cap.mul(nonRevocProofXList.r_prime));

        PointG2 s = nonRevocationCredentialSignature
                .witness_signature
                .sigma_i
                .add(credentialRevocationPublicKey.h_cap.mul(nonRevocProofXList.r_prime_prime));

        PointG2 u = nonRevocationCredentialSignature
                .witness_signature
                .u_i
                .add(credentialRevocationPublicKey.h_cap.mul(nonRevocProofXList.r_prime_prime_prime));

        return new  NonRevocProofCList(e, d, a, g, w, s, u);
    }

    private static NonRevocProofXList createTauListParams() {

        return new NonRevocProofXList(
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement(),
                new GroupOrderElement());
    }
}
