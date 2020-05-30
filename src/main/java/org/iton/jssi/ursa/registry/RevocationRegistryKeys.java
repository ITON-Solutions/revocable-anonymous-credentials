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

package org.iton.jssi.ursa.registry;

import org.iton.jssi.ursa.anoncred.CredentialRevocationPublicKey;
import org.iton.jssi.ursa.pair.CryptoException;
import org.iton.jssi.ursa.pair.GroupOrderElement;
import org.iton.jssi.ursa.pair.Pair;
import org.iton.jssi.ursa.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RevocationRegistryKeys {

    private static final Logger LOG = LoggerFactory.getLogger(RevocationRegistryKeys.class);

    private RevocationPublicKey revocationPublicKey;
    private RevocationPrivateKey revocationPrivateKey;

    private RevocationRegistryKeys(RevocationPublicKey revocationPublicKey,
                                  RevocationPrivateKey revocationPrivateKey)
    {
        this.revocationPublicKey = revocationPublicKey;
        this.revocationPrivateKey = revocationPrivateKey;
    }

    public RevocationPublicKey getRevocationPublicKey() {
        return revocationPublicKey;
    }

    public RevocationPrivateKey getRevocationPrivateKey() {
        return revocationPrivateKey;
    }

    public static RevocationRegistryKeys create(
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            int maxCredentials) throws CryptoException
    {

        LOG.debug("Create Revocation registry keys...");
        GroupOrderElement gamma = new GroupOrderElement();

        Pair z = Pair.pair(credentialRevocationPublicKey.g, credentialRevocationPublicKey.g_dash);
        GroupOrderElement pow = GroupOrderElement.fromBytes(Bytes.toBytes(maxCredentials + 1));
        pow = gamma.powmod(pow);
        z = z.pow(pow);
        return new RevocationRegistryKeys(new RevocationPublicKey(z), new RevocationPrivateKey(gamma));
    }
}
