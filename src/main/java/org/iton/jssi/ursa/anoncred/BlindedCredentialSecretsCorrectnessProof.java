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

package org.iton.jssi.ursa.anoncred;

import org.iton.jssi.ursa.anoncred.util.BigNumber;
import org.iton.jssi.ursa.anoncred.util.Helper;
import org.iton.jssi.ursa.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;
import static org.iton.jssi.ursa.anoncred.util.BigNumber.LARGE_MTILDE;
import static org.iton.jssi.ursa.anoncred.util.BigNumber.LARGE_VPRIME_TILDE;

public class BlindedCredentialSecretsCorrectnessProof {

    private static final Logger LOG = LoggerFactory.getLogger(BlindedCredentialSecretsCorrectnessProof.class);

    public BigInteger c;                   // Fiat-Shamir challenge hash
    public BigInteger v_dash_cap;          // Value to prove knowledge of `u` construction in `BlindedCredentialSecrets`
    public Map<String, BigInteger> m_caps; // Values for proving knowledge of committed values
    public Map<String, BigInteger> r_caps; // Blinding values for m_caps

    public BlindedCredentialSecretsCorrectnessProof(
            BigInteger c,
            BigInteger v_dash_cap,
            Map<String, BigInteger> m_caps,
            Map<String, BigInteger> r_caps)
    {
        this.c = c;
        this.v_dash_cap = v_dash_cap;
        this.m_caps = m_caps;
        this.r_caps = r_caps;
    }

    public static BlindedCredentialSecretsCorrectnessProof create(
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            PrimaryBlindedCredentialSecretsFactors primaryBlindedCredentialSecretsFactors,
            BigInteger nonce,
            CredentialValues credentialValues)
    {

        LOG.debug("Create Blinded credential secrets correctness proof...");
        BigInteger v_dash_tilde = BigNumber.random(LARGE_VPRIME_TILDE);
//        v_dash_tilde = new BigInteger("270298478417095479220290594584939047494346369147130625108591856876117642868384581126125783954421760120577629749641226846121717203028533346759100110785712141640560127342213391944485939721690475622269446352076925746031688944474239002873223246082659545835862203324527060373195507623970150203119643721810930015338375780971579576793925694267571879407191707981773572210444428542162229763930927238351508059716880136045903789030790652455164621105198032833923907461267590398142725202091851402685994954911410422001894367996342090912801956301144967233896238762263421366525202483740826305755322465437271844697666681531541885251237239852498850301814902435663338193987341790780575615266435607053286091159594260827197490278550174978", 10);

        Map<String, BigInteger> m_tildes = new LinkedHashMap<>();
        Map<String, BigInteger> r_tildes = new LinkedHashMap<>();

        byte[] values = new byte[0];
        BigInteger u_tilde = credentialPrimaryPublicKey.s.modPow(v_dash_tilde, credentialPrimaryPublicKey.n);

        for (String attr : credentialValues.getValues().keySet()){
            CredentialValue value = credentialValues.getValues().get(attr);

            if(value.type == CredentialValue.Type.KNOWN){
                continue;
            }

            BigInteger m_tilde = BigNumber.random(LARGE_MTILDE);
//            m_tilde = new BigInteger("10838856720335086997514319917662253919386665513436731291879876033663916796845905483096428365331456535021555195228705107240745433186472885370026158281452488750543836812854534798015", 10);
            BigInteger pk_r = credentialPrimaryPublicKey.r.get(attr);

            switch(value.type){
                case HIDDEN:{
                    u_tilde = u_tilde.multiply(pk_r.modPow(m_tilde, credentialPrimaryPublicKey.n)).mod(credentialPrimaryPublicKey.n);
                    break;
                }
                case COMMITMENT:{
                    BigInteger r_tilde = BigNumber.random(LARGE_MTILDE);
//                    r_tilde = new BigInteger("10838856720335086997514319917662253919386665513436731291879876033663916796845905483096428365331456535021555195228705107240745433186472885370026158281452488750543836812854534798015", 10);
                    BigInteger commitment_tilde = Helper.getPedersenCommitment(
                            credentialPrimaryPublicKey.z,
                            m_tilde,
                            credentialPrimaryPublicKey.s,
                            r_tilde,
                            credentialPrimaryPublicKey.n);

                    r_tildes.put(attr, r_tilde);

                    values = Bytes.concat(values, asUnsignedByteArray(commitment_tilde));
                    BigInteger ca_value = primaryBlindedCredentialSecretsFactors.committed_attributes.get(attr);
                    values = Bytes.concat(values, asUnsignedByteArray(ca_value));
                    break;
                }
            }

            m_tildes.put(attr, m_tilde);
        }

        values = Bytes.concat(values, asUnsignedByteArray(primaryBlindedCredentialSecretsFactors.u));
        values = Bytes.concat(values, asUnsignedByteArray(u_tilde));
        values = Bytes.concat(values, asUnsignedByteArray(nonce));
        BigInteger c = new BigInteger(1, Helper.hash(values));

        BigInteger v_dash_cap = c.multiply(primaryBlindedCredentialSecretsFactors.v_prime).add(v_dash_tilde);

        Map<String, BigInteger> m_caps = new LinkedHashMap<>();
        Map<String, BigInteger> r_caps = new LinkedHashMap<>();

        for (String attr : m_tildes.keySet()) {
            CredentialValue value = credentialValues.getValues().get(attr);
            BigInteger m_tilde = m_tildes.get(attr);

            switch(value.type){
                case HIDDEN:{
                    BigInteger m_cap = m_tilde.add(c.multiply(value.value));
                    m_caps.put(attr, m_cap);
                    break;
                }
                case COMMITMENT:{
                    BigInteger m_cap = m_tilde.add(c.multiply(value.value));
                    BigInteger r_cap = r_tildes.get(attr).add(c.multiply(value.blinding));

                    m_caps.put(attr, m_cap);
                    r_caps.put(attr, r_cap);
                    break;
                }
            }
        }

        return new BlindedCredentialSecretsCorrectnessProof(
                c,
                v_dash_cap,
                m_caps,
                r_caps);
    }

    public static boolean check(
            BlindedCredentialSecrets blindedCredentialSecrets,
            BlindedCredentialSecretsCorrectnessProof blindedCredentialSecretsCorrectnessProof,
            BigInteger nonce,
            CredentialPrimaryPublicKey credentialPrimaryPublicKey)
    {
        LOG.debug("Check Blinded credential secrets correctness proof...");
        byte[] values = new byte[0];

        BigInteger u_cap = blindedCredentialSecrets.u.modInverse(credentialPrimaryPublicKey.n)
                .modPow(blindedCredentialSecretsCorrectnessProof.c, credentialPrimaryPublicKey.n)
                .multiply(credentialPrimaryPublicKey.s.modPow(blindedCredentialSecretsCorrectnessProof.v_dash_cap, credentialPrimaryPublicKey.n))
                .mod(credentialPrimaryPublicKey.n);

        for(String attr : blindedCredentialSecrets.hidden_attributes) {
            BigInteger pk_r = credentialPrimaryPublicKey.r.get(attr);
            BigInteger m_cap = blindedCredentialSecretsCorrectnessProof.m_caps.get(attr);
            u_cap = u_cap.multiply(pk_r.modPow(m_cap, credentialPrimaryPublicKey.n)).mod(credentialPrimaryPublicKey.n);
        }

        for(String key : blindedCredentialSecrets.committed_attributes.keySet()) {

            BigInteger value = blindedCredentialSecrets.committed_attributes.get(key);
            BigInteger m_cap = blindedCredentialSecretsCorrectnessProof.m_caps.get(key);

            BigInteger comm_att_cap = value.modInverse(credentialPrimaryPublicKey.n)
                    .modPow(blindedCredentialSecretsCorrectnessProof.c, credentialPrimaryPublicKey.n)
                    .multiply(Helper.getPedersenCommitment(
                            credentialPrimaryPublicKey.z,
                            m_cap,
                            credentialPrimaryPublicKey.s,
                            blindedCredentialSecretsCorrectnessProof.r_caps.get(key),
                            credentialPrimaryPublicKey.n))
                    .mod(credentialPrimaryPublicKey.n);

            values = Bytes.concat(values, asUnsignedByteArray(comm_att_cap));
            values = Bytes.concat(values, asUnsignedByteArray(value));
        }

        values = Bytes.concat(values, asUnsignedByteArray(blindedCredentialSecrets.u));
        values = Bytes.concat(values, asUnsignedByteArray(u_cap));
        values = Bytes.concat(values, asUnsignedByteArray(nonce));

        BigInteger c = new BigInteger(1, Helper.hash(values));
        boolean valid = blindedCredentialSecretsCorrectnessProof.c.equals(c);

        if(!valid) {
            LOG.error("Invalid Blinded credential secret correctness proof");
            return false;
        }

        LOG.debug("Check Blinded credential secrets correctness proof... OK");
        return true;
    }

}
