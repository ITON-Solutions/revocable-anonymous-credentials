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

import org.iton.jssi.ursa.pair.GroupOrderElement;
import org.iton.jssi.ursa.pair.PointG1;
import org.iton.jssi.ursa.pair.PointG2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CredentialRevocationKeys {

    private static final Logger LOG = LoggerFactory.getLogger(CredentialRevocationKeys.class);

    private CredentialRevocationPublicKey credentialRevocationPublicKey;
    private CredentialRevocationPrivateKey credentialRevocationPrivateKey;

    private CredentialRevocationKeys(CredentialRevocationPublicKey credentialRevocationPublicKey, CredentialRevocationPrivateKey credentialRevocationPrivateKey){
        this.credentialRevocationPublicKey = credentialRevocationPublicKey;
        this.credentialRevocationPrivateKey = credentialRevocationPrivateKey;
    }

    public CredentialRevocationKeys(){
        this(null, null);
    }

    public CredentialRevocationPublicKey getCredentialRevocationPublicKey() {
        return credentialRevocationPublicKey;
    }

    public CredentialRevocationPrivateKey getCredentialRevocationPrivateKey() {
        return credentialRevocationPrivateKey;
    }

    public static CredentialRevocationKeys create(){

        LOG.debug("Create Credential revocation keys...");
        PointG1 h = new PointG1();
        PointG1 h0 = new PointG1();
        PointG1 h1 = new PointG1();
        PointG1 h2 = new PointG1();
        PointG1 h_tilde = new PointG1();
        PointG1 g = new PointG1();

        PointG2 u = new PointG2();
        PointG2 h_cap = new PointG2();

        GroupOrderElement x = new GroupOrderElement();
        GroupOrderElement sk = new GroupOrderElement();
        PointG2 g_dash = new PointG2();

        PointG1 pk = g.mul(sk);
        PointG2 y = h_cap.mul(x);

        CredentialRevocationPublicKey revocationPublicKey = new CredentialRevocationPublicKey(g, g_dash, h, h0, h1, h2, h_tilde, h_cap, u, pk, y);
        CredentialRevocationPrivateKey revocationPrivateKey = new CredentialRevocationPrivateKey(x, sk);

        return new CredentialRevocationKeys(revocationPublicKey, revocationPrivateKey);
    }
}
