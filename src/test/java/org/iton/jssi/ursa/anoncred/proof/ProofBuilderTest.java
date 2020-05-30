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

import org.iton.jssi.ursa.anoncred.CredentialSchema;
import org.iton.jssi.ursa.anoncred.CredentialValues;
import org.iton.jssi.ursa.anoncred.NonCredentialSchema;
import org.iton.jssi.ursa.anoncred.PrimaryCredentialSignature;
import org.iton.jssi.ursa.anoncred.CredentialPrimaryPublicKey;
import org.iton.jssi.ursa.anoncred.CredentialSignature;
import org.iton.jssi.ursa.anoncred.issuer.IssuerEmulator;
import org.iton.jssi.ursa.anoncred.prover.ProverEmulator;
import org.iton.jssi.ursa.pair.CryptoException;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ProofBuilderTest {

    private ProverEmulator prover = new ProverEmulator();
    private IssuerEmulator issuer = new IssuerEmulator();

    @Test
    void initEqProof() throws CryptoException {
        Map<String, BigInteger> common_attributes = new HashMap<>();
        common_attributes.put("master_secret", prover.m1_t());
        CredentialPrimaryPublicKey pk = issuer.getCredentialPrimaryPublicKey();
        CredentialSchema cred_schema = issuer.getCredentialSchema();
        NonCredentialSchema non_cred_schema_elems = issuer.getNonCredentialSchema();
        PrimaryCredentialSignature credential = prover.getPrimaryCredentialSignature();
        SubProofRequest sub_proof_request = prover.getSubProofRequest();

        BigInteger m2_tilde = new BigInteger(1, prover.getNonRevocationInitProof().tau_list_params.m2.toBytes());

        PrimaryEqualInitProof init_eq_proof = PrimaryEqualProof.init(
                common_attributes,
                pk,
                credential,
                cred_schema,
                non_cred_schema_elems,
                sub_proof_request,
                m2_tilde);

        assertEquals(init_eq_proof, prover.getPrimaryEqInitProof());

    }

    @Test
    public void initNeProof() {

        CredentialPrimaryPublicKey pk = issuer.getCredentialPrimaryPublicKey();
        PrimaryEqualInitProof init_eq_proof = prover.getPrimaryEqInitProof();
        Predicate predicate = prover.predicate();
        CredentialValues credential_values = issuer.getCredentialValues();

        PrimaryPredicateInequalityInitProof init_ne_proof = PrimaryPredicateInequalityProof.init(
                pk,
                init_eq_proof.m_tilde,
                credential_values,
                predicate);

        assertEquals(prover.getPrimaryNeInitProof(), init_ne_proof);
    }

    @Test
    public void  initPrimaryProof() throws CryptoException {

        CredentialPrimaryPublicKey pk = issuer.getCredentialPrimaryPublicKey();
        CredentialSchema credential_schema = issuer.getCredentialSchema();
        NonCredentialSchema non_credential_schema = issuer.getNonCredentialSchema();
        CredentialSignature credential = prover.getCredentialSignature();
        CredentialValues credential_values = issuer.getCredentialValues();
        SubProofRequest sub_proof_request = prover.getSubProofRequest();
        Map<String, BigInteger> common_attributes = prover.getProofCommonAttributes();
        BigInteger m2_tilde = new BigInteger(1, prover.getNonRevocationInitProof().tau_list_params.m2.toBytes());

        PrimaryInitProof init_proof = PrimaryProof.init(
                common_attributes,
                pk,
                credential.p_credential,
                credential_values,
                credential_schema,
                non_credential_schema,
                sub_proof_request,
                m2_tilde);

        assertEquals(prover.getPrimaryInitProof(), init_proof);
    }

    @Test
    public void finalizeEqProof() {

        BigInteger c_hash = prover.getAggregatedProof().c_hash;
        PrimaryEqualInitProof init_proof = prover.getPrimaryEqInitProof();
        CredentialValues credential_values = issuer.getCredentialValues();
        NonCredentialSchema non_credential_schema = issuer.getNonCredentialSchema();
        CredentialSchema credential_schema = issuer.getCredentialSchema();
        SubProofRequest sub_proof_request = prover.getSubProofRequest();

        PrimaryEqualProof eq_proof = PrimaryEqualProof.finalize(
                init_proof,
                c_hash,
                credential_schema,
                non_credential_schema,
                credential_values,
                sub_proof_request);
        assertEquals(prover.getPrimaryEqProof(), eq_proof);
    }

    @Test
    public void finalizeNeProof() {

        BigInteger c_h = prover.getAggregatedProof().c_hash;
        PrimaryPredicateInequalityInitProof ne_proof = prover.getPrimaryNeInitProof();
        PrimaryEqualProof eq_proof = prover.getPrimaryEqProof();

        PrimaryPredicateInequalityProof neProof = PrimaryPredicateInequalityProof.finalize(c_h, ne_proof, eq_proof);
        assertEquals(prover.getPrimaryPredicateNeProof(), neProof);
    }

    @Test
    public void finalizePrimaryProof() {

        PrimaryInitProof proof = prover.getPrimaryInitProof();
        BigInteger c_h = prover.getAggregatedProof().c_hash;
        CredentialSchema credential_schema = issuer.getCredentialSchema();
        NonCredentialSchema non_credential_schema = issuer.getNonCredentialSchema();;
        CredentialValues credential_values = issuer.getCredentialValues();
        SubProofRequest sub_proof_request = prover.getSubProofRequest();

        PrimaryProof primaryProof = PrimaryProof.finalize(
                proof,
                c_h,
                credential_schema,
                non_credential_schema,
                credential_values,
                sub_proof_request);


        assertEquals(prover.getPrimaryProof(), primaryProof);
    }
}