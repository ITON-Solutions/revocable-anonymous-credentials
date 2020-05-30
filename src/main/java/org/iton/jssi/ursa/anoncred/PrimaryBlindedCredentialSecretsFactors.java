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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.iton.jssi.ursa.anoncred.util.BigNumber.LARGE_VPRIME;

public class PrimaryBlindedCredentialSecretsFactors {

    private static final Logger LOG = LoggerFactory.getLogger(PrimaryBlindedCredentialSecretsFactors.class);

    public BigInteger u;
    public BigInteger v_prime;
    public List<String> hidden_attributes;
    public Map<String, BigInteger> committed_attributes;

    public PrimaryBlindedCredentialSecretsFactors(
            BigInteger u,
            BigInteger v_prime,
            List<String> hidden_attributes,
            Map<String, BigInteger> committed_attributes)
    {
        this.u = u;
        this.v_prime = v_prime;
        this.hidden_attributes = hidden_attributes;
        this.committed_attributes = committed_attributes;
    }

    public static PrimaryBlindedCredentialSecretsFactors create(
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            CredentialValues credentialValues)
    {
        LOG.debug("Create Primary blinded credential secrets factors...");
        BigInteger v_prime = BigNumber.random(LARGE_VPRIME);
//        v_prime = new BigInteger("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290", 10);

        // Hidden attributes are combined in this value
        List<String> hidden_attributes = credentialValues.getValues().entrySet().stream()
                .filter(entry -> entry.getValue().type == CredentialValue.Type.HIDDEN)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());

        BigInteger u = credentialPrimaryPublicKey.s.modPow(v_prime, credentialPrimaryPublicKey.n);

        for(String attr : hidden_attributes){
            BigInteger pk_r = credentialPrimaryPublicKey.r.get(attr);
            CredentialValue credentialValue = credentialValues.getValues().get(attr);
            u = u.multiply(pk_r.modPow(credentialValue.value, credentialPrimaryPublicKey.n)).mod(credentialPrimaryPublicKey.n);
        }

        Map<String, BigInteger> committed_attributes = new LinkedHashMap<>();

        for(String attr : credentialValues.getValues().keySet()) {
            CredentialValue credentialValue = credentialValues.getValues().get(attr);
            if(credentialValue.type != CredentialValue.Type.COMMITMENT) {
                continue;
            }
            committed_attributes.put(attr, Helper.getPedersenCommitment(
                    credentialPrimaryPublicKey.s,
                    credentialValue.blinding,
                    credentialPrimaryPublicKey.z,
                    credentialValue.value,
                    credentialPrimaryPublicKey.n
            ));
        }

        return new PrimaryBlindedCredentialSecretsFactors(u, v_prime, hidden_attributes, committed_attributes);
    }

}
