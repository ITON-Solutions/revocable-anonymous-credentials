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

import org.iton.jssi.ursa.anoncred.CredentialSchema;
import org.iton.jssi.ursa.anoncred.CredentialValues;
import org.iton.jssi.ursa.anoncred.NonCredentialSchema;

public class InitProof {

    PrimaryInitProof primary_init_proof;
    NonRevocInitProof non_revoc_init_proof;
    CredentialValues credential_values;
    SubProofRequest sub_proof_request;
    CredentialSchema credential_schema;
    NonCredentialSchema non_credential_schema;

    public InitProof(
            PrimaryInitProof primary_init_proof,
            NonRevocInitProof non_revoc_init_proof,
            CredentialValues credential_values,
            SubProofRequest sub_proof_request,
            CredentialSchema credential_schema,
            NonCredentialSchema non_credential_schema)
    {
        this.primary_init_proof = primary_init_proof;
        this.non_revoc_init_proof = non_revoc_init_proof;
        this.credential_values = credential_values;
        this.sub_proof_request = sub_proof_request;
        this.credential_schema = credential_schema;
        this.non_credential_schema = non_credential_schema;
    }
}
