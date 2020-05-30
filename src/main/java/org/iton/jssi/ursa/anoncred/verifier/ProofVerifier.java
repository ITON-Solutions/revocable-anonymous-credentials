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

package org.iton.jssi.ursa.anoncred.verifier;

import org.iton.jssi.ursa.anoncred.CredentialSchema;
import org.iton.jssi.ursa.anoncred.NonCredentialSchema;
import org.iton.jssi.ursa.anoncred.CredentialPrimaryPublicKey;
import org.iton.jssi.ursa.anoncred.CredentialPublicKey;
import org.iton.jssi.ursa.anoncred.CredentialRevocationPublicKey;
import org.iton.jssi.ursa.anoncred.proof.*;
import org.iton.jssi.ursa.anoncred.util.Helper;
import org.iton.jssi.ursa.pair.CryptoException;
import org.iton.jssi.ursa.pair.GroupOrderElement;
import org.iton.jssi.ursa.registry.RevocationPublicKey;
import org.iton.jssi.ursa.registry.RevocationRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;
import static org.iton.jssi.ursa.anoncred.util.BigNumber.ITERATION;
import static org.iton.jssi.ursa.anoncred.util.BigNumber.LARGE_E_START_VALUE;

public class ProofVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(ProofVerifier.class);

    List<VerifiableCredential> credentials = new ArrayList<>();
    Map<String, BigInteger> common_attributes = new HashMap<>();

    public ProofVerifier() {
    }

    public ProofVerifier(List<VerifiableCredential> credentials, Map<String, BigInteger> common_attributes) {
        this.credentials = credentials;
        this.common_attributes = common_attributes;
    }

    /**
     * Attributes that are supposed to have same value across all subproofs.
     * The verifier first enters attribute names in the hashmap before proof verification starts.
     * The hashmap is again updated during verification of sub proofs by the blinded value of attributes (`m_hat`s in paper)
     *
     * @param attr_name
     */
    public void addCommonAttr(String attr_name) {
        common_attributes.put(attr_name, null);
    }

    /**
     *
     * @param subProofRequest
     * @param credentialSchema
     * @param nonCredentialSchema
     * @param credentialPublicKey
     * @param revocationPublicKey
     * @param revocationRegistry
     *
     * Add sub proof request to proof verifier.
     * The order of sub-proofs is important: both Prover and Verifier should use the same order.
     *
     * Example
     *
     * CredentialSchemaBuilder builder = CredentialSchema.CredentialSchemaBuilder().builder();
     * builder.addAttr("sex");
     * CredentialSchema credentialSchema = builder.build();
     *
     * NonCredentialSchemaBuilder nonBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonBuilder.build();
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, false);
     *
     *  SubProofRequest.SubProofRequestBuilder  subProofRequestBuilder = SubProofRequest.builder();
     *  subProofRequestBuilder.addRevealedAttr("sex").unwrap();
     *  SubProofRequest subProofRequest = subProofRequestBuilder.build();
     *
     *  ProofVerifier proofVerifier = Verifier.createProofVerifier();
     *
     *  proofVerifier.addSubProofRequest(subProofRequest,
     *                                   credentialSchema,
     *                                   nonCredentialSchema,
     *                                   credentialDefinition.getCredentialPublicKey(),
     *                                   null,
     *                                   null);
     *
     */
    public void addSubProofRequest(
            SubProofRequest subProofRequest,
            CredentialSchema credentialSchema,
            NonCredentialSchema nonCredentialSchema,
            CredentialPublicKey credentialPublicKey,
            RevocationPublicKey revocationPublicKey,
            RevocationRegistry revocationRegistry) {

        credentials.add(new VerifiableCredential(
                credentialPublicKey,
                subProofRequest,
                credentialSchema,
                nonCredentialSchema,
                revocationPublicKey,
                revocationRegistry));
    }

    /**
     *
     * @param proof
     * @param nonce
     * @return
     * @throws CryptoException
     *
     * Verifies proof.
     *
     * Example
     *
     * CredentialSchemaBuilder builder = CredentialSchema.CredentialSchemaBuilder().builder();
     * builder.addAttr("sex");
     * CredentialSchema credentialSchema = builder.build();
     *
     * NonCredentialSchemaBuilder nonBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonBuilder.build();
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, false);
     *
     * MasterSecret masterSecret = MasterSecret.create();
     *
     * CredentialValues.CredentialValuesBuilder credentialValuesBuilder = CredentialValues.builder();
     * credentialValuesBuilder.addHidden("master_secret", masterSecret.ms);
     * credentialValuesBuilder.addKnown("name", "5944657099558967239210949258394887428692050081607692519917050011144233115103");
     * CredentialValues credentialValues = credentialValuesBuilder.build();
     *
     * BigInteger credentialNonce = BigNumber.random(LARGE_NONCE);
     * BlindedCredentials blindedCredentials = Prover.blindCredentialSecrets(
     *               credentialDefinition.getCredentialPublicKey(),
     *               credentialDefinition.getCredentialKeyCorrectnessProof(),
     *               credentialValues,
     *               credentialNonce);
     * BigInteger issuanceNonce = BigNumber.random(LARGE_NONCE);
     *
     * SignedCredential signedCredential = Issuer.signCredential(
     *                  "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
     *                  blindedCredentials.getBlindedCredentialSecrets(),
     *                  blindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
     *                  credentialNonce,
     *                  issuanceNonce,
     *                  credentialValues,
     *                  credentialDefinition.getCredentialPublicKey(),
     *                  credentialDefinition.getCredentialPrivateKey());
     *
     * boolean result = Prover.processCredentialSignature(signedCredential.credentialSignature,
     *                  credentialValues,
     *                  signedCredential.signatureCorrectnessProof,
     *                  blindedCredentials.credentialSecretsBlindingFactors,
     *                  credentialDefinition.getCredentialPublicKey(),
     *                  issuanceNonce,
     *                  null, null, ull);
     *
     * SubProofRequest.SubProofRequestBuilder  subProofRequestBuilder = SubProofRequest.builder();
     * subProofRequestBuilder.addRevealedAttr("sex").unwrap();
     * SubProofRequest subProofRequest = subProofRequestBuilder.build();
    
     * ProofBuilder proofBuilder = new ProofBuilder();
     * proofBuilder.addCommonAttr("master_secret").unwrap();
     * proofBuilder.addSubProofRequest(subProofRequest,
     *                                  credentialSchema,
     *                                  nonCredentialSchema,
     *                                  signedCredential.credentialSignature,
     *                                  credentialValues,
     *                                  credentialDefinition.getCredentialPublicKey(),
     *                                  null,
     *                                  null);
     *
     * BigInteger proofRequestNonce = BigNumber.random(LARGE_NONCE);
     * Proof proof = proofBuilder.build(proofRequestNonce);
     *
     * ProofVerifier proofVerifier = Verifier.createProofVerifier();
     * proofVerifier.addSubProofRequest(subProofRequest,
     *                                 credentialSchema,
     *                                 nonCredentialSchema,
     *                                 credentialDefinition.getCredentialPublicKey(),
     *                                 null,
     *                                 null);
     *  boolean verified = proofVerifier.verify(proof, proofRequestNonce);
     */
    public boolean verify(Proof proof, BigInteger nonce) throws CryptoException {

        if(!checkVerifyParamsConsistency(credentials, proof)){
            return false;
        }

        List<byte[]> tau_list = new ArrayList<>();

        for(int idx = 0; idx < proof.proofs.size(); idx++) {
            SubProof proof_item = proof.proofs.get(idx);
            VerifiableCredential credential = credentials.get(idx);

            if(proof_item.non_revoc_proof != null
                    && credential.pub_key.r_key != null
                    && credential.rev_key_pub != null
                    && credential.rev_reg != null)
            {
                tau_list.addAll(verifyNonRevocationProof(
                        credential.pub_key.r_key,
                        credential.rev_reg,
                        credential.rev_key_pub,
                        proof.aggregated_proof.c_hash,
                        proof_item.non_revoc_proof).toList());
            }

            // Check that `m_hat`s of all common attributes are same.
            // Also `m_hat` for each common attribute must be present in each sub proof
            Set<String> attr_names = common_attributes.keySet();
            for(String attr_name : attr_names) {
                if (proof_item.primary_proof.eq_proof.m.containsKey(attr_name)) {
                    BigInteger m_hat = proof_item.primary_proof.eq_proof.m.get(attr_name);

                    BigInteger value = common_attributes.get(attr_name);
                    if(value != null) {
                        if (!value.equals(m_hat)) {
                            LOG.error(String.format("Blinded value for common attribute '%s' different across sub proofs", attr_name));
                            return false;
                        }
                    } else {
                        common_attributes.put(attr_name, m_hat);
                    }
                } else {
                    // `m_hat` for common attribute not present in sub proof
                    LOG.error(String.format("Blinded value for common attribute '%s' not found in proof.m", attr_name));
                    return false;
                }
            }

            tau_list.addAll(verifyPrimaryProof(
                    credential.pub_key.p_key,
                    proof.aggregated_proof.c_hash,
                    proof_item.primary_proof,
                    credential.credential_schema,
                    credential.non_credential_schema,
                    credential.sub_proof_request).stream().map(item -> asUnsignedByteArray(item)).collect(Collectors.toList()));
        }

        List<byte[]> values = new ArrayList<>();
        values.addAll(tau_list);
        values.addAll(proof.aggregated_proof.c_list);
        values.add(asUnsignedByteArray(nonce));

        BigInteger c_hver = new BigInteger(1, Helper.hash(values));

        if(!c_hver.equals(proof.aggregated_proof.c_hash)){
            return false;
        }
        return true;
    }

    private boolean checkVerifyParamsConsistency(List<VerifiableCredential> credentials, Proof proof) {

        if (proof.proofs.size() != credentials.size()) {
            LOG.error("Invalid proof length");
            return false;
        }

        Iterator<SubProof> proofs_iterator =  proof.proofs.listIterator();
        Iterator<VerifiableCredential> credentials_iterator = credentials.listIterator();

        while(proofs_iterator.hasNext() && credentials_iterator.hasNext()){
            SubProof proof_for_credential = proofs_iterator.next();
            VerifiableCredential credential = credentials_iterator.next();

            Set<String> proof_revealed_attrs = proof_for_credential.primary_proof.eq_proof.revealed_attrs.keySet();
            if(!proof_revealed_attrs.containsAll(credential.sub_proof_request.revealed_attrs)){
                LOG.error("Proof revealed attributes not correspond to requested attributes");
                return false;
            }

            Set<Predicate> proof_predicates = proof_for_credential.primary_proof.ne_proofs.stream()
                    .map(item -> item.predicate).collect(Collectors.toSet());

            if(!proof_predicates.containsAll(credential.sub_proof_request.predicates)){
                LOG.error("Proof predicates not correspond to requested predicates");
                return false;
            }
        }

        return true;
    }

    private static NonRevocProofTauList verifyNonRevocationProof(
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            RevocationRegistry revocationRegistry,
            RevocationPublicKey revocationPublicKey,
            BigInteger c_hash,
            NonRevocProof proof) throws CryptoException {

        GroupOrderElement ch_num_z = GroupOrderElement.fromBytes(asUnsignedByteArray(c_hash));

        NonRevocProofTauList t_hat_expected_values = Helper.createTauListExpectedValues(
                credentialRevocationPublicKey,
                revocationRegistry,
                revocationPublicKey,
                proof.c_list);
        NonRevocProofTauList t_hat_calc_values = Helper.createTauListValues(
                credentialRevocationPublicKey,
                revocationRegistry,
                proof.x_list,
                proof.c_list);

        return new NonRevocProofTauList(
                t_hat_expected_values.t1.mul(ch_num_z).add(t_hat_calc_values.t1),
                t_hat_expected_values.t2.mul(ch_num_z).add(t_hat_calc_values.t2),
                t_hat_expected_values.t3.pow(ch_num_z).mul(t_hat_calc_values.t3),
                t_hat_expected_values.t4.pow(ch_num_z).mul(t_hat_calc_values.t4),
                t_hat_expected_values.t5.mul(ch_num_z).add(t_hat_calc_values.t5),
                t_hat_expected_values.t6.mul(ch_num_z).add(t_hat_calc_values.t6),
                t_hat_expected_values.t7.pow(ch_num_z).mul(t_hat_calc_values.t7),
                t_hat_expected_values.t8.pow(ch_num_z).mul(t_hat_calc_values.t8));
    }

    private static List<BigInteger> verifyPrimaryProof(
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            BigInteger c_hash,
            PrimaryProof primaryProof,
            CredentialSchema credentialSchema,
            NonCredentialSchema nonCredentialSchema,
            SubProofRequest subProofRequest)
    {

        List<BigInteger> t_hat = verifyEq(
                credentialPrimaryPublicKey,
                primaryProof.eq_proof,
                c_hash,
                credentialSchema,
                nonCredentialSchema,
                subProofRequest);

        for(PrimaryPredicateInequalityProof ne_proof : primaryProof.ne_proofs) {
            t_hat.addAll(verifyNePredicate(credentialPrimaryPublicKey, ne_proof, c_hash));
        }
        return t_hat;
    }

    public static List<BigInteger> verifyEq(
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            PrimaryEqualProof primaryEqualProof,
            BigInteger c_hash,
            CredentialSchema credentialSchema,
            NonCredentialSchema nonCredentialSchema,
            SubProofRequest subProofRequest)
    {
        // Union two lists
        List<String> unrevealed_attrs = Stream.concat(nonCredentialSchema.attrs.stream(), credentialSchema.attrs.stream())
                .distinct()
                .collect(Collectors.toList());


        unrevealed_attrs = unrevealed_attrs.stream()
                .filter(item -> !subProofRequest.revealed_attrs.contains(item))
                .collect(Collectors.toList());

        BigInteger t1 = Helper.calc_teq(
                credentialPrimaryPublicKey,
                primaryEqualProof.a_prime,
                primaryEqualProof.e,
                primaryEqualProof.v,
                primaryEqualProof.m,
                primaryEqualProof.m2,
                unrevealed_attrs);

        BigInteger rar = primaryEqualProof.a_prime.modPow(LARGE_E_START_VALUE, credentialPrimaryPublicKey.n);


        for(String attr : primaryEqualProof.revealed_attrs.keySet()){
            BigInteger encoded_value = primaryEqualProof.revealed_attrs.get(attr);
            BigInteger cur_r = credentialPrimaryPublicKey.r.get(attr);

            if(cur_r == null){
                LOG.error(String.format("Value by key '%s' not found in pk.r", attr));
                return null;
            }

            rar = cur_r.modPow(encoded_value, credentialPrimaryPublicKey.n).multiply(rar).mod(credentialPrimaryPublicKey.n);
        }

        BigInteger t2 = credentialPrimaryPublicKey.z
                .multiply(rar.modInverse(credentialPrimaryPublicKey.n)).mod(credentialPrimaryPublicKey.n) //(z * (1/rar mod n) mod n)
                .modInverse(credentialPrimaryPublicKey.n)
                .modPow(c_hash, credentialPrimaryPublicKey.n);

        BigInteger t = t1.multiply(t2).mod(credentialPrimaryPublicKey.n);
        List<BigInteger> result = new ArrayList<>();
        result.add(t);
        return result;
    }

    public static List<BigInteger> verifyNePredicate(
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            PrimaryPredicateInequalityProof primaryPredicateInequalityProof,
            BigInteger c_hash)
    {

        List<BigInteger> tau_list = Helper.calc_tne(
                credentialPrimaryPublicKey,
                primaryPredicateInequalityProof.u,
                primaryPredicateInequalityProof.r,
                primaryPredicateInequalityProof.mj,
                primaryPredicateInequalityProof.alpha,
                primaryPredicateInequalityProof.t,
                primaryPredicateInequalityProof.predicate.isLess());

        for(int i = 0; i < ITERATION; i++) {
            BigInteger cur_t = primaryPredicateInequalityProof.t.get(String.valueOf(i));

            if(cur_t == null){
                LOG.error(String.format("Value by key '%d' not found in proof.t", i));
                return null;
            }

            tau_list.set(i, cur_t
                    .modPow(c_hash, credentialPrimaryPublicKey.n)
                    .modInverse(credentialPrimaryPublicKey.n)
                    .multiply(tau_list.get(i))
                    .mod(credentialPrimaryPublicKey.n));
        }

        BigInteger delta = primaryPredicateInequalityProof.t.get("DELTA");
        if(delta == null){
            LOG.error(String.format("Value by key '%s' not found in proof.t", "DELTA"));
            return null;
        }

        BigInteger delta_prime = delta;
        if(primaryPredicateInequalityProof.predicate.isLess()){
            delta_prime = delta.modInverse(credentialPrimaryPublicKey.n);
        }

        tau_list.set(ITERATION, credentialPrimaryPublicKey.z
                .modPow(primaryPredicateInequalityProof.predicate.getDeltaPrime(), credentialPrimaryPublicKey.n)
                .multiply(delta_prime)
                .modPow(c_hash, credentialPrimaryPublicKey.n)
                .modInverse(credentialPrimaryPublicKey.n)
                .multiply(tau_list.get(ITERATION))
                .mod(credentialPrimaryPublicKey.n));

        tau_list.set(ITERATION + 1,  delta
                .modPow(c_hash, credentialPrimaryPublicKey.n)
                .modInverse(credentialPrimaryPublicKey.n)
                .multiply(tau_list.get(ITERATION + 1))
                .mod(credentialPrimaryPublicKey.n));

        return tau_list;
    }
}
