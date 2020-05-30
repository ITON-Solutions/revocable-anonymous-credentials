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
import org.iton.jssi.ursa.pair.PointG2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Revocation Registry contains accumulator.
// Must be published by Issuer on a tamper-evident and highly available storage
// Used by prover to prove that a credential hasn't revoked by the issuer
// isDefault - Type of issuance.
// If true all indices are assumed to be issued and initial accumulator is calculated over all indices
// If false nothing is issued initially accumulator is 1
public class RevocationRegistry {

    private static final Logger LOG = LoggerFactory.getLogger(RevocationRegistry.class);

    public Accumulator accumulator;

    public RevocationRegistry(Accumulator accumulator){
        this.accumulator = accumulator;
    }

    public static RevocationRegistry create(
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            RevocationPrivateKey revocationPrivateKey,
            int maxCredentials,
            boolean isDefault)
    {
        LOG.debug("Create Revocation registry...");

        Accumulator accumulator = new Accumulator(PointG2.infinity());

        if (isDefault) {

            for (int i = 1; i <= maxCredentials; i++) {
                int index = maxCredentials + 1 - i;
                accumulator = new Accumulator(accumulator.add(Tail.create(
                        index,
                        credentialRevocationPublicKey.g_dash,
                        revocationPrivateKey.gamma)));
            }
        }

        return new RevocationRegistry(accumulator);
    }
}
