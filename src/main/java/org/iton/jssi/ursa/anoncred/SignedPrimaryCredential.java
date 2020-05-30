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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

public class SignedPrimaryCredential {

    private static final Logger LOG = LoggerFactory.getLogger(SignedPrimaryCredential.class);

    public BigInteger a;
    public BigInteger q;

    public SignedPrimaryCredential(BigInteger a, BigInteger q){
        this.a = a;
        this.q = q;
    }

    public static SignedPrimaryCredential create(
            CredentialPublicKey credentialPublicKey,
            CredentialPrivateKey credentialPrivateKey,
            BigInteger credentialContext,
            CredentialValues credentialValues,
            BigInteger v,
            BlindedCredentialSecrets blindedCredentialSecrets,
            BigInteger e)
    {
        LOG.debug("Sign Primary credential...");
        CredentialPrimaryPublicKey credentialPrimaryPublicKey = credentialPublicKey.p_key;
        CredentialPrimaryPrivateKey credentialPrimaryPrivateKey = credentialPrivateKey.p_key;
        BigInteger rx = credentialPrimaryPublicKey.s.modPow(v, credentialPrimaryPublicKey.n);

        if (!blindedCredentialSecrets.u.equals(BigInteger.ZERO)) {
            rx = rx.multiply(blindedCredentialSecrets.u).mod(credentialPrimaryPublicKey.n);
        }

        rx = rx.multiply(credentialPrimaryPublicKey.rctxt.modPow(credentialContext, credentialPrimaryPublicKey.n)).mod(credentialPrimaryPublicKey.n);

        for(String attr : credentialValues.getValues().keySet()){
            CredentialValue value = credentialValues.getValues().get(attr);
            if(value.type != CredentialValue.Type.KNOWN){
                continue;
            }
            BigInteger pk_r = credentialPrimaryPublicKey.r.get(attr);
            rx = pk_r.modPow(value.value, credentialPrimaryPublicKey.n).multiply(rx).mod(credentialPrimaryPublicKey.n);
        }

        BigInteger q = credentialPrimaryPublicKey.z.multiply(rx.modInverse(credentialPrimaryPublicKey.n)).mod(credentialPrimaryPublicKey.n);
        BigInteger n = credentialPrimaryPrivateKey.p.multiply(credentialPrimaryPrivateKey.q);
        BigInteger e_inverse = e.modInverse(n);
        BigInteger a = q.modPow(e_inverse, credentialPrimaryPublicKey.n);

        return new SignedPrimaryCredential(a, q);
    }

}
