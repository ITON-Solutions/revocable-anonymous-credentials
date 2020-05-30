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

package org.iton.jssi.ursa.anoncred.zerokp;

import org.iton.jssi.ursa.anoncred.CredentialSchema;
import org.iton.jssi.ursa.anoncred.CredentialValues;
import org.iton.jssi.ursa.anoncred.NonCredentialSchema;
import org.iton.jssi.ursa.anoncred.proof.SubProofRequest;
import org.iton.jssi.ursa.anoncred.prover.MasterSecret;
import org.iton.jssi.ursa.anoncred.util.BigNumber;

import java.math.BigInteger;

import static org.iton.jssi.ursa.anoncred.util.BigNumber.LARGE_NONCE;

public class ZeroKP {

    public static final String PROVER_DID = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";
    public static final String LINK_SECRET = "master_secret";

    public static BigInteger getCredentialIssuanceNonce(){
        BigInteger nonce = BigNumber.random(LARGE_NONCE);
        nonce = new BigInteger("56533754654551822200471", 10);
        return nonce;
    }

    public static BigInteger getCredentialNonce(){
        BigInteger nonce = BigNumber.random(LARGE_NONCE);
        nonce = new BigInteger("400156503076115782845986", 10);
        return nonce;
    }

    public static CredentialSchema gvtCredentialSchema() {
        CredentialSchema.CredentialSchemaBuilder builder = CredentialSchema.builder();
        builder.addAttr("name");
        builder.addAttr("sex");
        builder.addAttr("age");
        builder.addAttr("height");
        return builder.build();
    }

    public static CredentialSchema xyzCredentialSchema() {
        CredentialSchema.CredentialSchemaBuilder builder = CredentialSchema.builder();
        builder.addAttr("status");
        builder.addAttr("period");
        return builder.build();
    }

    public static CredentialSchema pqrCredentialSchema() {
        CredentialSchema.CredentialSchemaBuilder builder = CredentialSchema.builder();
        builder.addAttr("name");
        builder.addAttr("address");
        return builder.build();
    }

    public static NonCredentialSchema nonCredentialSchema() {
        NonCredentialSchema.NonCredentialSchemaBuilder builder = NonCredentialSchema.builder();
        builder.addAttr("master_secret");
        return builder.build();
    }

    public static CredentialValues gvtCredentialValues(MasterSecret master_secret) {
        CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
        builder.addHidden("master_secret", master_secret.ms);
        builder.addKnown("name", "1139481716457488690172217916278103335");
        builder.addKnown("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103");
        builder.addKnown("age", "28");
        builder.addKnown("height", "175");
        return builder.build();
    }

    public static CredentialValues xyzCredentialValues(MasterSecret master_secret) {
        CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
        builder.addHidden("master_secret", master_secret.ms);
        builder.addKnown("status", "51792877103171595686471452153480627530895");
        builder.addKnown("period", "8");
        return builder.build();
    }

    public static CredentialValues pqrCredentialValues(MasterSecret master_secret) {
        CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
        builder.addHidden("master_secret", master_secret.ms);
        builder.addKnown("name", "1139481716457488690172217916278103335");
        builder.addKnown("address", "51792877103171595686471452153480627530891");
        return builder.build();
    }

    public static CredentialValues pqrCredentialValues_1(MasterSecret master_secret) {
        CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
        builder.addHidden("master_secret", master_secret.ms);
        builder.addKnown("name", "7181645748869017221791627810333511394");
        builder.addKnown("address", "51792877103171595686471452153480627530891");
        return builder.build();
    }

    public static SubProofRequest gvtSubProofRequest() {
        SubProofRequest.SubProofRequestBuilder builder = SubProofRequest.builder();
        builder.addRevealedAttr("name");
        builder.addPredicate("age", "GE", 18);
        return builder.build();
    }

    public static SubProofRequest xyzSubProofRequest() {
        SubProofRequest.SubProofRequestBuilder builder = SubProofRequest.builder();
        builder.addRevealedAttr("status");
        builder.addPredicate("period", "GE", 4);
        return builder.build();
    }

    public static SubProofRequest pqrSubProofRequest() {
        SubProofRequest.SubProofRequestBuilder builder = SubProofRequest.builder();
        builder.addRevealedAttr("address");
        return builder.build();
    }

    public static SubProofRequest gvtSubProofRequest_1() {
        SubProofRequest.SubProofRequestBuilder builder = SubProofRequest.builder();
        builder.addRevealedAttr("sex");
        return builder.build();
    }
}
