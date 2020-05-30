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
import org.iton.jssi.ursa.anoncred.*;
import org.iton.jssi.ursa.anoncred.CredentialPrimaryPublicKey;
import org.iton.jssi.ursa.anoncred.util.BigNumber;
import org.iton.jssi.ursa.anoncred.util.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

import static org.iton.jssi.ursa.anoncred.util.BigNumber.*;
import static org.iton.jssi.ursa.anoncred.util.BigNumber.LARGE_E_START_VALUE;

public class PrimaryEqualProof {

    private static final Logger LOG = LoggerFactory.getLogger(PrimaryEqualProof.class);

    public Map<String /* attr_name of revealed */, BigInteger> revealed_attrs;
    public BigInteger a_prime;
    public BigInteger e;
    public BigInteger v;
    public Map<String /* attr_name of all except revealed */, BigInteger> m;
    public BigInteger m2;

    @JsonCreator
    public PrimaryEqualProof(
            @JsonProperty("revealed_attrs") Map<String, BigInteger> revealed_attrs,
            @JsonProperty("a_prime") BigInteger a_prime,
            @JsonProperty("e") BigInteger e,
            @JsonProperty("v") BigInteger v,
            @JsonProperty("m") Map<String, BigInteger> m,
            @JsonProperty("m2") BigInteger m2)
    {
        this.revealed_attrs = revealed_attrs;
        this.a_prime = a_prime;
        this.e = e;
        this.v = v;
        this.m = m;
        this.m2 = m2;
    }

    public static PrimaryEqualInitProof init(
            Map<String, BigInteger> common_attributes,
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            PrimaryCredentialSignature primaryCredentialSignature,
            CredentialSchema credentialSchema,
            NonCredentialSchema nonCredentialSchema,
            SubProofRequest subProofRequest,
            BigInteger m2_t)
    {

        BigInteger m2_tilde = m2_t == null ? BigNumber.random(LARGE_MVECT) : m2_t;
        BigInteger r =  BigNumber.random(LARGE_VPRIME);
        r = new BigInteger("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290", 10);
        BigInteger e_tilde =  BigNumber.random(LARGE_ETILDE);
        e_tilde = new BigInteger("162083298053730499878539835193560156486733663622707027216327685550780519347628838870322946818623352681120371349972731968874009673965057322", 10);
        BigInteger v_tilde =  BigNumber.random(LARGE_VTILDE);
        v_tilde = new BigInteger("241132863422049783305938184561371219250127488499746090592218003869595412171810997360214885239402274273939963489505434726467041932541499422544431299362364797699330176612923593931231233163363211565697860685967381420219969754969010598350387336530924879073366177641099382257720898488467175132844984811431059686249020737675861448309521855120928434488546976081485578773933300425198911646071284164884533755653094354378714645351464093907890440922615599556866061098147921890790915215227463991346847803620736586839786386846961213073783437136210912924729098636427160258710930323242639624389905049896225019051952864864612421360643655700799102439682797806477476049234033513929028472955119936073490401848509891547105031112859155855833089675654686301183778056755431562224990888545742379494795601542482680006851305864539769704029428620446639445284011289708313620219638324467338840766574612783533920114892847440641473989502440960354573501", 10);

        List<String> unrevealed_attrs = new ArrayList<>();
        unrevealed_attrs.addAll(nonCredentialSchema.attrs);
        unrevealed_attrs.addAll(credentialSchema.attrs);

        unrevealed_attrs = unrevealed_attrs.stream()
                .filter(item -> !subProofRequest.revealed_attrs.contains(item))
                .collect(Collectors.toList());

        Map<String, BigInteger> m_tilde = new HashMap<>(common_attributes);

        for (String attr : unrevealed_attrs) {
            if (!m_tilde.containsKey(attr)) {
                BigInteger large_mvect = BigNumber.random(LARGE_MVECT);
                large_mvect = new BigInteger("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338", 10);
                m_tilde.put(attr, large_mvect);
            }
        }

        BigInteger a_prime = credentialPrimaryPublicKey
                .s
                .modPow(r, credentialPrimaryPublicKey.n)
                .multiply(primaryCredentialSignature.a)
                .mod(credentialPrimaryPublicKey.n);

        BigInteger e_prime = primaryCredentialSignature.e.subtract(LARGE_E_START_VALUE);
        BigInteger v_prime = primaryCredentialSignature.v.subtract(primaryCredentialSignature.e.multiply(r));

        BigInteger t = Helper.calc_teq(
                credentialPrimaryPublicKey,
                a_prime,
                e_tilde,
                v_tilde,
                m_tilde,
                m2_tilde,
                unrevealed_attrs);

        return new PrimaryEqualInitProof(
                a_prime,
                t,
                e_tilde,
                e_prime,
                v_tilde,
                v_prime,
                m_tilde,
                m2_tilde,
                primaryCredentialSignature.m_2);
    }

    public static PrimaryEqualProof finalize(
            PrimaryEqualInitProof primaryEqualInitProof,
            BigInteger challenge,
            CredentialSchema credentialSchema,
            NonCredentialSchema nonCredentialSchema,
            CredentialValues credentialValues,
            SubProofRequest subProofRequest) {

        BigInteger e = challenge
                .multiply(primaryEqualInitProof.e_prime)
                .add(primaryEqualInitProof.e_tilde);

        BigInteger v = challenge
                .multiply(primaryEqualInitProof.v_prime)
                .add(primaryEqualInitProof.v_tilde);

        Map<String, BigInteger> m_hat = new HashMap<>();

        List<String> unrevealed_attrs = new ArrayList<>();
        unrevealed_attrs.addAll(nonCredentialSchema.attrs);
        unrevealed_attrs.addAll(credentialSchema.attrs);

        unrevealed_attrs = unrevealed_attrs.stream()
                .filter(item -> !subProofRequest.revealed_attrs.contains(item))
                .collect(Collectors.toList());

        for(String key : unrevealed_attrs) {

            BigInteger cur_mtilde = primaryEqualInitProof.m_tilde.get(key);
            if(cur_mtilde == null){
                LOG.error(String.format("Value by key '%s' not found in init_proof.m_tilde", key));
                return null;
            }

            CredentialValue cur_val = credentialValues.getValues().get(key);
            if(cur_val == null){
                LOG.error(String.format("Value by key '%s' not found in attributes_values", key));
                return null;
            }
            // val = cur_mtilde + (cur_val * challenge)
            BigInteger val = challenge
                    .multiply(cur_val.value)
                    .add(cur_mtilde);

            m_hat.put(key, val);
        }

        BigInteger m2 = challenge
                .multiply(primaryEqualInitProof.m2)
                .add(primaryEqualInitProof.m2_tilde);

        Map<String, BigInteger> revealed_attrs_with_values = new LinkedHashMap<>();

        for(String attr : subProofRequest.revealed_attrs) {
            CredentialValue value = credentialValues.getValues().get(attr);
            if(value == null){
                LOG.error(String.format("Encoded value for '%s' not found in Sub proof request", attr));
                return null;
            }
            revealed_attrs_with_values.put(attr, value.value);
        }

        return new  PrimaryEqualProof(
                revealed_attrs_with_values,
                primaryEqualInitProof.a_prime,
                e,
                v,
                m_hat,
                m2);
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PrimaryEqualProof that = (PrimaryEqualProof) o;

        if (!revealed_attrs.equals(that.revealed_attrs)) return false;
        if (!a_prime.equals(that.a_prime)) return false;
        if (!e.equals(that.e)) return false;
        if (!v.equals(that.v)) return false;
        if (!m.equals(that.m)) return false;
        return m2.equals(that.m2);
    }
}
