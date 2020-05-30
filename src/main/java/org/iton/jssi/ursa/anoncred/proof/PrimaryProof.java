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
import org.iton.jssi.ursa.anoncred.CredentialSchema;
import org.iton.jssi.ursa.anoncred.CredentialValues;
import org.iton.jssi.ursa.anoncred.NonCredentialSchema;
import org.iton.jssi.ursa.anoncred.PrimaryCredentialSignature;
import org.iton.jssi.ursa.anoncred.CredentialPrimaryPublicKey;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class PrimaryProof {

    public PrimaryEqualProof eq_proof;
    public List<PrimaryPredicateInequalityProof> ne_proofs;

    @JsonCreator
    public PrimaryProof(
            @JsonProperty("eq_proofs") PrimaryEqualProof eq_proof,
            @JsonProperty("ne_proofs") List<PrimaryPredicateInequalityProof> ne_proofs)
    {
        this.eq_proof = eq_proof;
        this.ne_proofs = ne_proofs;
    }

    public static PrimaryInitProof init(
            Map<String, BigInteger> common_attributes,
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            PrimaryCredentialSignature primaryCredentialSignature,
            CredentialValues credentialValues,
            CredentialSchema credentialSchema,
            NonCredentialSchema nonCredentialSchema,
            SubProofRequest subProofRequest,
            BigInteger m2_tilde)
    {

        PrimaryEqualInitProof eq_proof = PrimaryEqualProof.init(
                common_attributes,
                credentialPrimaryPublicKey,
                primaryCredentialSignature,
                credentialSchema,
                nonCredentialSchema,
                subProofRequest,
                m2_tilde);

        List<PrimaryPredicateInequalityInitProof> ne_proofs = new ArrayList<>();

        for (Predicate predicate : subProofRequest.predicates) {
            PrimaryPredicateInequalityInitProof ne_proof = PrimaryPredicateInequalityProof.init(
                    credentialPrimaryPublicKey,
                    eq_proof.m_tilde,
                    credentialValues,
                    predicate);
            ne_proofs.add(ne_proof);
        }

        return new PrimaryInitProof(eq_proof, ne_proofs);
    }

    public static PrimaryProof finalize(
            PrimaryInitProof primaryInitProof,
            BigInteger challenge,
            CredentialSchema credentialSchema,
            NonCredentialSchema nonCredentialSchema,
            CredentialValues credentialValues,
            SubProofRequest subProofRequest)
    {

        PrimaryEqualProof eq_proof = PrimaryEqualProof.finalize(
                primaryInitProof.eq_proof,
                challenge,
                credentialSchema,
                nonCredentialSchema,
                credentialValues,
                subProofRequest);

        List<PrimaryPredicateInequalityProof> ne_proofs = new ArrayList<>();

        for(PrimaryPredicateInequalityInitProof init_ne_proof : primaryInitProof.ne_proofs) {
            PrimaryPredicateInequalityProof ne_proof = PrimaryPredicateInequalityProof.finalize(challenge, init_ne_proof, eq_proof);
            ne_proofs.add(ne_proof);
        }

        return new PrimaryProof(eq_proof, ne_proofs);
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PrimaryProof that = (PrimaryProof) o;

        if (!eq_proof.equals(that.eq_proof)) return false;
        return ne_proofs.equals(that.ne_proofs);
    }
}
