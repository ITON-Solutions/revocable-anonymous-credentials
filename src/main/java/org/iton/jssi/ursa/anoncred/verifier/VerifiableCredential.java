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
import org.iton.jssi.ursa.anoncred.CredentialPublicKey;
import org.iton.jssi.ursa.anoncred.proof.SubProofRequest;
import org.iton.jssi.ursa.registry.RevocationPublicKey;
import org.iton.jssi.ursa.registry.RevocationRegistry;

public class VerifiableCredential {
    CredentialPublicKey pub_key;
    SubProofRequest sub_proof_request;
    CredentialSchema credential_schema;
    NonCredentialSchema non_credential_schema;
    RevocationPublicKey rev_key_pub;
    RevocationRegistry rev_reg;

    public VerifiableCredential(
            CredentialPublicKey pub_key,
            SubProofRequest sub_proof_request,
            CredentialSchema credential_schema,
            NonCredentialSchema non_credential_schema,
            RevocationPublicKey rev_key_pub,
            RevocationRegistry rev_reg)
    {
        this.pub_key = pub_key;
        this.sub_proof_request = sub_proof_request;
        this.credential_schema = credential_schema;
        this.non_credential_schema = non_credential_schema;
        this.rev_key_pub = rev_key_pub;
        this.rev_reg = rev_reg;
    }
}
