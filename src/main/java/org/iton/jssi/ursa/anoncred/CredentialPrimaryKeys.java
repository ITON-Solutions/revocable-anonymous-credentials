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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

public class CredentialPrimaryKeys {

    private static final Logger LOG = LoggerFactory.getLogger(CredentialPrimaryKeys.class);

    private CredentialPrimaryPublicKey credentialPrimaryPublicKey;
    private CredentialPrimaryPrivateKey credentialPrimaryPrivateKey;
    private CredentialPrimaryPublicKeyMetadata credentialPrimaryPublicKeyMetadata;

    private CredentialPrimaryKeys(CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            CredentialPrimaryPrivateKey credentialPrimaryPrivateKey,
            CredentialPrimaryPublicKeyMetadata credentialPrimaryPublicKeyMetadata){

        this.credentialPrimaryPublicKey = credentialPrimaryPublicKey;
        this.credentialPrimaryPrivateKey = credentialPrimaryPrivateKey;
        this.credentialPrimaryPublicKeyMetadata = credentialPrimaryPublicKeyMetadata;
    }

    public CredentialPrimaryPublicKey getCredentialPrimaryPublicKey() {
        return credentialPrimaryPublicKey;
    }

    public CredentialPrimaryPrivateKey getCredentialPrimaryPrivateKey() {
        return credentialPrimaryPrivateKey;
    }

    public CredentialPrimaryPublicKeyMetadata getCredentialPrimaryPublicKeyMetadata() {
        return credentialPrimaryPublicKeyMetadata;
    }

    public static CredentialPrimaryKeys create(CredentialSchema credentialSchema, NonCredentialSchema nonCredentialSchema){

        LOG.debug("Create Credential primary keys...");
//        BigInteger pSafe = BigNumber.safePrime(LARGE_PRIME, new SecureRandom());
        BigInteger pSafe = new BigInteger("120430509814986158732045374064934973507616476525867014934828468252976991714972269692688316597063527545129054387774732029488840684607562805535977252862538948899165894840779214605269894546552551865788862336071132835313026926795640689884826055805140566049564859898906987222193387348904720674957705400641017159047", 10);
//        BigInteger qSafe = BigNumber.safePrime(LARGE_PRIME, new SecureRandom());
        BigInteger qSafe = new BigInteger("142846641910505433550984630330323765392348590170959350818643102770064192625231026792763037513209755553329617455315131525113319361147698893311478123207441253980124094528744801237404993842629410482061528079465322255707650334932244837391961420979725305770442528622510585530611103074940648833243687051204119916207", 10);

        BigInteger p = pSafe.shiftRight(1);
        BigInteger q = qSafe.shiftRight(1);

        BigInteger n = pSafe.multiply(qSafe);

        BigInteger s = BigNumber.randomQr(n);
        BigInteger xz = BigNumber.genX(p, q);

        Map<String, BigInteger> xr = new LinkedHashMap<>();
        for(String attribute : nonCredentialSchema.attrs) {
            xr.put(attribute, BigNumber.genX(p, q));
        }

        for (String attribute : credentialSchema.attrs) {
            xr.put(attribute, BigNumber.genX(p, q));
        }

        Map<String, BigInteger> r = new LinkedHashMap<>();
        for (String key : xr.keySet())  {
            r.put(key, s.modPow(xr.get(key), n));
        }

        BigInteger z = s.modPow(xz, n);

        BigInteger rctxt = s.modPow(BigNumber.genX(p, q), n);

        CredentialPrimaryPublicKey credentialPrimaryPublicKey = new CredentialPrimaryPublicKey(n, s, rctxt, r, z);
        CredentialPrimaryPrivateKey credentialPrimaryPrivateKey = new CredentialPrimaryPrivateKey(p, q);
        CredentialPrimaryPublicKeyMetadata credentialPrimaryPublicKeyMetadata = new CredentialPrimaryPublicKeyMetadata(xz, xr);

        return new CredentialPrimaryKeys(
                credentialPrimaryPublicKey,
                credentialPrimaryPrivateKey,
                credentialPrimaryPublicKeyMetadata);
    }
}
