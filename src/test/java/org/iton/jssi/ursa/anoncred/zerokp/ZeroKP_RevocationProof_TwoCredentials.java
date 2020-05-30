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

import org.iton.jssi.ursa.anoncred.*;
import org.iton.jssi.ursa.anoncred.CredentialDefinition;
import org.iton.jssi.ursa.anoncred.issuer.Issuer;
import org.iton.jssi.ursa.anoncred.proof.Proof;
import org.iton.jssi.ursa.anoncred.proof.ProofBuilder;
import org.iton.jssi.ursa.anoncred.proof.SubProofRequest;
import org.iton.jssi.ursa.anoncred.prover.MasterSecret;
import org.iton.jssi.ursa.anoncred.prover.Prover;
import org.iton.jssi.ursa.anoncred.util.BigNumber;
import org.iton.jssi.ursa.anoncred.verifier.ProofVerifier;
import org.iton.jssi.ursa.anoncred.verifier.Verifier;
import org.iton.jssi.ursa.pair.CryptoException;
import org.iton.jssi.ursa.registry.RevocationRegistryDefinition;
import org.iton.jssi.ursa.registry.SimpleTailsAccessor;
import org.iton.jssi.ursa.registry.Witness;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.iton.jssi.ursa.anoncred.util.BigNumber.LARGE_NONCE;
import static org.iton.jssi.ursa.anoncred.zerokp.ZeroKP.LINK_SECRET;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ZeroKP_RevocationProof_TwoCredentials {

    @Test
    public void verify() throws CryptoException {

        // 1. Prover creates master secret
        MasterSecret masterSecret = MasterSecret.create();

        // Issuer creates GVT credential
        // 2. Issuer creates GVT credential schema
        CredentialSchema gvtCredentialSchema = ZeroKP.gvtCredentialSchema();
        NonCredentialSchema gvtNonCredentialSchema = ZeroKP.nonCredentialSchema();

        // 3. Issuer creates GVT credential definition(with revocation keys)
        CredentialDefinition gvtCredentialDefinition = Issuer.createCredentialDefinition(
                gvtCredentialSchema,
                gvtNonCredentialSchema,
                true);

        // 4. Issuer creates GVT revocation registry with Issuance on demand type
        int gvtMaxCredentials = 5;
        boolean gvtIsDefault = false;
        RevocationRegistryDefinition gvtRevocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtMaxCredentials,
                gvtIsDefault);

        SimpleTailsAccessor gvtTailAccessor = SimpleTailsAccessor.create(gvtRevocationRegistryDefinition.getRevocationTailsGenerator());

        // 5. Issuer creates and sign credential values
        CredentialValues gvtCredentialValues = ZeroKP.gvtCredentialValues(MasterSecret.create());

        // 6. Issuer creates GVT nonce used by Prover to create correctness proof for blinded secrets
        BigInteger gvtCredentialNonce = ZeroKP.getCredentialNonce();

        // 7. Prover blinds GVT hidden attributes
        BlindedCredentials gvtBlindedCredentials = Prover.blindCredentialSecrets(
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtCredentialDefinition.getCredentialKeyCorrectnessProof(),
                gvtCredentialValues,
                gvtCredentialNonce);

        // 8. Prover creates GVT nonce used by Issuer to create correctness proof for signature
        BigInteger gvtCredentialIssuanceNonce = ZeroKP.getCredentialIssuanceNonce();

        // 9. Issuer signs GVT credential values
        int gvtRevocationIdx = 1;
        SignedCredential gvtSignedCredential = Issuer.signCredentialWithRevocation(
                ZeroKP.PROVER_DID,
                gvtBlindedCredentials.getBlindedCredentialSecrets(),
                gvtBlindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
                gvtCredentialNonce,
                gvtCredentialIssuanceNonce,
                gvtCredentialValues,
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtCredentialDefinition.getCredentialPrivateKey(),
                gvtRevocationIdx,
                gvtMaxCredentials,
                gvtIsDefault,
                gvtRevocationRegistryDefinition.getRevocationRegistry(),
                gvtRevocationRegistryDefinition.getRevocationPrivateKey(),
                gvtTailAccessor);

        // 10. Prover creates GVT witness
        Witness gvtWitness = Witness.create(
                gvtRevocationIdx,
                gvtMaxCredentials,
                gvtIsDefault,
                gvtSignedCredential.revocationRegistryDelta,
                gvtTailAccessor);


        // 11. Prover processes GVT credential signature
        Prover.processCredentialSignature(
                gvtSignedCredential.credentialSignature,
                gvtCredentialValues,
                gvtSignedCredential.signatureCorrectnessProof,
                gvtBlindedCredentials.getCredentialSecretsBlindingFactors(),
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtCredentialIssuanceNonce,
                gvtRevocationRegistryDefinition.getRevocationPublicKey(),
                gvtRevocationRegistryDefinition.getRevocationRegistry(),
                gvtWitness);

        // Issuer creates XYZ credential
        // 12. Issuer creates XYZ credential schema
        CredentialSchema xyzCredentialSchema = ZeroKP.xyzCredentialSchema();
        NonCredentialSchema xyzNonCredentialSchema = ZeroKP.nonCredentialSchema();

        // 13. Issuer creates XYZ credential definition (with revocation keys)
        CredentialDefinition xyzCredentialDefinition = Issuer.createCredentialDefinition(
                xyzCredentialSchema,
                xyzNonCredentialSchema,
                true);

        // 14. Issuer creates XYZ revocation registry with IssuanceByDefault type
        int xyzMaxCredentials = 5;
        boolean xyzIsDefault = false;
        RevocationRegistryDefinition xyzRevocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzMaxCredentials,
                xyzIsDefault);

        SimpleTailsAccessor xyzTailAccessor = SimpleTailsAccessor.create(xyzRevocationRegistryDefinition.getRevocationTailsGenerator());

        // 15. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
        BigInteger xyzCredentialNonce = ZeroKP.getCredentialNonce();

        // 16. Issuer creates XYZ credential values
        CredentialValues xyzCredentialValues = ZeroKP.xyzCredentialValues(MasterSecret.create());

        // 17. Prover blinds XYZ hidden attributes
        BlindedCredentials xyzBlindedCredentials = Prover.blindCredentialSecrets(
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzCredentialDefinition.getCredentialKeyCorrectnessProof(),
                xyzCredentialValues,
                xyzCredentialNonce);

        // 18. Prover creates nonce used by Issuer to create correctness proof for XYZ signature
        BigInteger xyzCredentialIssuanceNonce = ZeroKP.getCredentialIssuanceNonce();

        // 19. Issuer signs XYZ credential values
        int xyzRevocationIdx = 1;
        SignedCredential xyzSignedCredential = Issuer.signCredentialWithRevocation(
                ZeroKP.PROVER_DID,
                xyzBlindedCredentials.getBlindedCredentialSecrets(),
                xyzBlindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
                xyzCredentialNonce,
                xyzCredentialIssuanceNonce,
                xyzCredentialValues,
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzCredentialDefinition.getCredentialPrivateKey(),
                xyzRevocationIdx,
                xyzMaxCredentials,
                xyzIsDefault,
                xyzRevocationRegistryDefinition.getRevocationRegistry(),
                xyzRevocationRegistryDefinition.getRevocationPrivateKey(),
                xyzTailAccessor);

        // 20. Prover creates XYZ witness
        Witness xyzWitness = Witness.create(
                xyzRevocationIdx,
                xyzMaxCredentials,
                xyzIsDefault,
                xyzSignedCredential.revocationRegistryDelta,
                xyzTailAccessor);

        // 21. Prover processes XYZ credential signature
        Prover.processCredentialSignature(
                xyzSignedCredential.credentialSignature,
                xyzCredentialValues,
                xyzSignedCredential.signatureCorrectnessProof,
                xyzBlindedCredentials.getCredentialSecretsBlindingFactors(),
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzCredentialIssuanceNonce,
                xyzRevocationRegistryDefinition.getRevocationPublicKey(),
                xyzRevocationRegistryDefinition.getRevocationRegistry(),
                xyzWitness);

        // 22. Verifier creates sub proof request related to GVT credential
        SubProofRequest gvtSubProofRequest = ZeroKP.gvtSubProofRequest();

        // 23. Verifier creates sub proof request related to XYZ credential
        SubProofRequest xyzSubProofRequest = ZeroKP.xyzSubProofRequest();

        // 24. Verifier creates nonce
        BigInteger nonce = BigNumber.random(LARGE_NONCE);

        // 25. Prover creates proof for two sub proof requests
        ProofBuilder proofBuilder = new ProofBuilder();
        proofBuilder.addCommonAttr(LINK_SECRET);
        proofBuilder.addSubProofRequest(
                gvtSubProofRequest,
                gvtCredentialSchema,
                gvtNonCredentialSchema,
                gvtSignedCredential.credentialSignature,
                gvtCredentialValues,
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtRevocationRegistryDefinition.getRevocationRegistry(),
                gvtWitness);

        proofBuilder.addSubProofRequest(
                xyzSubProofRequest,
                xyzCredentialSchema,
                xyzNonCredentialSchema,
                xyzSignedCredential.credentialSignature,
                xyzCredentialValues,
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzRevocationRegistryDefinition.getRevocationRegistry(),
                xyzWitness);

        Proof proof = proofBuilder.build(nonce);

        // 26. Verifier verifies proof
        ProofVerifier proofVerifier = Verifier.createProofVerifier();
        proofVerifier.addSubProofRequest(
                gvtSubProofRequest,
                gvtCredentialSchema,
                gvtNonCredentialSchema,
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtRevocationRegistryDefinition.getRevocationPublicKey(),
                gvtRevocationRegistryDefinition.getRevocationRegistry());

        proofVerifier.addSubProofRequest(
                xyzSubProofRequest,
                xyzCredentialSchema,
                xyzNonCredentialSchema,
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzRevocationRegistryDefinition.getRevocationPublicKey(),
                xyzRevocationRegistryDefinition.getRevocationRegistry());

        assertTrue(proofVerifier.verify(proof, nonce));
    }
}
