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

package org.iton.jssi.ursa.anoncred.issuer;

import org.iton.jssi.ursa.anoncred.*;
import org.iton.jssi.ursa.anoncred.util.BigNumber;
import org.iton.jssi.ursa.anoncred.util.Helper;
import org.iton.jssi.ursa.pair.CryptoException;
import org.iton.jssi.ursa.registry.*;
import org.iton.jssi.ursa.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

// Trust source that provides credentials to prover.
public class Issuer {

    private static final Logger LOG = LoggerFactory.getLogger(Issuer.class);

    /**
     *
     * @param credentialSchema
     * @param nonCredentialSchema
     * @param isRevocable
     * @return CredentialDefinition
     *
     * Example
     *
     * CredentialSchemaBuilder credentialSchemaBuilder = CredentialSchema.CredentialSchemaBuilder().builder();
     * credentialSchemaBuilder.addAttr("name");
     * credentialSchemaBuilder.addAttr("sex").unwrap();
     * CredentialSchema credentialSchema = credentialSchemaBuilder.build();
     *
     * NonCredentialSchemaBuilder nonCredentialSchemaBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonCredentialSchemaBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonCredentialSchemaBuilder.build();
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, true)
     */
    public static CredentialDefinition createCredentialDefinition(CredentialSchema credentialSchema, NonCredentialSchema nonCredentialSchema, boolean isRevocable){

        CredentialRevocationKeys credentialRevocationKeys = new CredentialRevocationKeys();

        CredentialPrimaryKeys credentialPrimaryKeys = CredentialPrimaryKeys.create(credentialSchema, nonCredentialSchema);
        if(isRevocable){
            credentialRevocationKeys = CredentialRevocationKeys.create();
        }

        CredentialPublicKey credentialPublicKey = new CredentialPublicKey(
                credentialPrimaryKeys.getCredentialPrimaryPublicKey(),
                credentialRevocationKeys.getCredentialRevocationPublicKey());

        CredentialPrivateKey credentialPrivateKey = new CredentialPrivateKey(
                credentialPrimaryKeys.getCredentialPrimaryPrivateKey(),
                credentialRevocationKeys.getCredentialRevocationPrivateKey());

        CredentialKeyCorrectnessProof credentialKeyCorrectnessProof = CredentialKeyCorrectnessProof.create(
                credentialPrimaryKeys.getCredentialPrimaryPublicKey(),
                credentialPrimaryKeys.getCredentialPrimaryPrivateKey(),
                credentialPrimaryKeys.getCredentialPrimaryPublicKeyMetadata());

        return new CredentialDefinition(credentialPublicKey, credentialPrivateKey, credentialKeyCorrectnessProof);
    }

    /**
     * Creates and returns revocation registry definition
     *
     * @param credentialPublicKey
     * @param maxCredentials
     * @param isDefault
     * If true all indices are assumed to be issued and initial accumulator is calculated over all indices
     * If false nothing is issued initially accumulator is 1
     * @return RevocationRegistryDefinition
     * @throws CryptoException
     *
     * Example
     *
     * CredentialSchemaBuilder builder = CredentialSchema.CredentialSchemaBuilder().builder();
     * builder.addAttr("name");
     * builder.addAttr("sex");
     * CredentialSchema credentialSchema = builder.build();
     *
     * NonCredentialSchemaBuilder nonBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonBuilder.build();
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, true);
     * int maxCredentials = 5;
     * boolean isDefault = false;
     * RevocationRegistryDefinition revocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
     *               credentialDefinition.getCredentialPublicKey(),
     *               maxCredentials,
     *               isDefault);
     */
    public static RevocationRegistryDefinition createRevocationRegistryDefinition(
            CredentialPublicKey credentialPublicKey,
            int maxCredentials,
            boolean isDefault) throws CryptoException
    {
        LOG.debug("Create Revocation registry definition...");
        CredentialRevocationPublicKey credentialRevocationPublicKey = credentialPublicKey.r_key;

        RevocationRegistryKeys revocationRegistryKeys = RevocationRegistryKeys.create(
                credentialRevocationPublicKey,
                maxCredentials);

        RevocationRegistry revocationRegistry = RevocationRegistry.create(
                credentialRevocationPublicKey,
                revocationRegistryKeys.getRevocationPrivateKey(),
                maxCredentials,
                isDefault);

        RevocationTailsGenerator revocationTailsGenerator = new RevocationTailsGenerator(
                maxCredentials,
                revocationRegistryKeys.getRevocationPrivateKey().gamma,
                credentialRevocationPublicKey.g_dash);

        return new RevocationRegistryDefinition(
                revocationRegistryKeys.getRevocationPublicKey(),
                revocationRegistryKeys.getRevocationPrivateKey(),
                revocationRegistry,
                revocationTailsGenerator);
    }

    // In the anoncreds whitepaper, `credential context` is denoted by `m2`
    public static BigInteger createCredentialContext(String prover_id, Integer rev_idx){

        LOG.debug(String.format("Create Credential context: %s (index %d)", prover_id, rev_idx));
        rev_idx = rev_idx == null ? -1 : rev_idx;

        BigInteger prover_id_bn = BigNumber.encodeAttribute(prover_id, BigNumber.ByteOrder.LITTLE);
        BigInteger rev_idx_bn = BigNumber.encodeAttribute(rev_idx.toString(), BigNumber.ByteOrder.LITTLE);
        byte[] values = Bytes.concat(asUnsignedByteArray(prover_id_bn), asUnsignedByteArray(rev_idx_bn));
        return new BigInteger(1, Helper.hash(values));
    }

    /**
     * Revokes a credential by a revocationIndex in a given revocation registry
     *
     * @param revocationRegistry
     * @param maxCredentials
     * @param revocationIndex
     * @param revocationTailsAccessor
     * @return <E extends RevocationTailsAccessor> RevocationRegistryDelta
     *
     * Example
     *
     * CredentialSchemaBuilder builder = CredentialSchema.CredentialSchemaBuilder().builder();
     * builder.addAttr("name");
     * CredentialSchema credentialSchema = builder.build();
     *
     * NonCredentialSchemaBuilder nonBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonBuilder.build();
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, true);
     *
     * int maxCredentials = 5;
     * boolean isDefault = false;
     * RevocationRegistryDefinition revocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
     *               credentialDefinition.getCredentialPublicKey(),
     *               maxCredentials,
     *               isDefault);
     *
     * SimpleTailsAccessor accessor = SimpleTailsAccessor.create(revocationRegistryDefinition.getRevocationTailsGenerator());
     * MasterSecret masterSecret = MasterSecret.create();
     *
     * CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
     * builder.addHidden("master_secret", masterSecret.ms);
     * builder.addKnown("name", "1139481716457488690172217916278103335");
     * CredentialValues credentialValues = builder.build();
     *
     * BigInteger credentialNonce = BigNumber.random(LARGE_NONCE);
     * BlindedCredentials blindedCredentials = Prover.blindCredentialSecrets(
     *               credentialDefinition.getCredentialPublicKey(),
     *               credentialDefinition.getCredentialKeyCorrectnessProof(),
     *               credentialValues,
     *               credentialNonce);
     *
     * BigInteger issuanceNonce = BigNumber.random(LARGE_NONCE);
     *
     * int revocationIndex = 1;
     * SignedCredential signedCredential = Issuer.signCredentialWithRevocation(
     *                 "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
     *                 blindedCredentials.getBlindedCredentialSecrets(),
     *                 blindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
     *                 credentialNonce,
     *                 issuanceNonce,
     *                 credentialValues,
     *                 credentialDefinition.getCredentialPublicKey(),
     *                 credentialDefinition.getCredentialPrivateKey(),
     *                 revocationIndex,
     *                 maxCredentials,
     *                 isDefault,
     *                 revocationRegistryDefinition.getRevocationRegistry(),
     *                 revocationRegistryDefinition.getRevocationPrivateKey(),
     *                 accessor);
     *
     * Issuer.revokeCredential(
     *                 revocationRegistryDefinition.getRevocationRegistry(),
     *                 maxCredentials,
     *                 revocationIndex,
     *                 accessor);
     */
    public static <E extends RevocationTailsAccessor> RevocationRegistryDelta revokeCredential(
            RevocationRegistry revocationRegistry,
            int maxCredentials,
            int revocationIndex,
            E revocationTailsAccessor)
    {
        int index = maxCredentials + 1 - revocationIndex;
        Tail tail = revocationTailsAccessor.access(index);

        Accumulator previous = revocationRegistry.accumulator;
        revocationRegistry.accumulator = revocationRegistry.accumulator.sub(tail);

        List<Integer> issued = new ArrayList<>();
        List<Integer> revoked = new ArrayList<>();
        revoked.add(revocationIndex);
        return new RevocationRegistryDelta(
                previous,
                revocationRegistry.accumulator,
                issued,
                revoked);
    }

    /**
     *
     * @param revocationRegistry
     * @param maxCredentials
     * @param revocationIndex
     * @param revocationTailsAccessor
     * @return <E extends RevocationTailsAccessor> RevocationRegistryDelta
     *
     * Example
     *
     * CredentialSchemaBuilder builder = CredentialSchema.CredentialSchemaBuilder().builder();
     * builder.addAttr("name");
     * CredentialSchema credentialSchema = builder.build();
     *
     * NonCredentialSchemaBuilder nonBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonBuilder.build();
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, true);
     *
     * int maxCredentials = 5;
     * boolean isDefault = false;
     * RevocationRegistryDefinition revocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
     *               credentialDefinition.getCredentialPublicKey(),
     *               maxCredentials,
     *               isDefault);
     *
     * SimpleTailsAccessor accessor = SimpleTailsAccessor.create(revocationRegistryDefinition.getRevocationTailsGenerator());
     * MasterSecret masterSecret = MasterSecret.create();
     *
     * CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
     * builder.addHidden("master_secret", masterSecret.ms);
     * builder.addKnown("name", "1139481716457488690172217916278103335");
     * CredentialValues credentialValues = return builder.build()
     *
     *  BigInteger credentialNonce = BigNumber.random(LARGE_NONCE);
     *  BlindedCredentials blindedCredentials = Prover.blindCredentialSecrets(
     *               credentialDefinition.getCredentialPublicKey(),
     *               credentialDefinition.getCredentialKeyCorrectnessProof(),
     *               credentialValues,
     *               credentialNonce);
     *
     *  BigInteger issuanceNonce = BigNumber.random(LARGE_NONCE);
     *
     *  int revocationIndex = 1;
     *  SignedCredential signedCredential = Issuer.signCredentialWithRevocation(
     *                 "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
     *                 blindedCredentials.getBlindedCredentialSecrets(),
     *                 blindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
     *                 credentialNonce,
     *                 issuanceNonce,
     *                 credentialValues,
     *                 credentialDefinition.getCredentialPublicKey(),
     *                 credentialDefinition.getCredentialPrivateKey(),
     *                 revocationIndex,
     *                 maxCredentials,
     *                 isDefault,
     *                 revocationRegistryDefinition.getRevocationRegistry(),
     *                 revocationRegistryDefinition.getRevocationPrivateKey(),
     *                 accessor);
     *
     *  RevocationRegistryDelta revocationRegistryDelta = Issuer.revokeCredential(
     *                 revocationRegistryDefinition.getRevocationRegistry(),
     *                 maxCredentials,
     *                 revocationIndex,
     *                 accessor);
     *
     *  revocationRegistryDelta = Issuer.restoreCredential(
     *                 revocationRegistryDefinition.getRevocationRegistry(),
     *                 maxCredentials,
     *                 revocationIndex,
     *                 accessor);
     */
    public static <E extends RevocationTailsAccessor> RevocationRegistryDelta restoreCredential(
            RevocationRegistry revocationRegistry,
            int maxCredentials,
            int revocationIndex,
            E revocationTailsAccessor)
    {
        int index = maxCredentials + 1 - revocationIndex;
        Tail tail = revocationTailsAccessor.access(index);

        Accumulator previous = revocationRegistry.accumulator;
        revocationRegistry.accumulator = revocationRegistry.accumulator.add(tail);

        List<Integer> issued = new ArrayList<>();
        issued.add(revocationIndex);
        List<Integer> revoked = new ArrayList<>();

         return new RevocationRegistryDelta(
                previous,
                revocationRegistry.accumulator,
                issued,
                revoked);
    }

    /**
     * Signs credential values with primary keys only.
     *
     * @param prover_id
     * @param blindedCredentialSecrets
     * @param blindedCredentialSecretsCorrectnessProof
     * @param credentialNonce
     * @param credentialIssuanceNonce
     * @param credentialValues
     * @param credentialPublicKey
     * @param credentialPrivateKey
     * @return SignedCredential
     *
     * Example
     *
     * CredentialSchemaBuilder builder = CredentialSchema.CredentialSchemaBuilder().builder();
     * builder.addAttr("sex");
     * CredentialSchema credentialSchema = builder.build();
     *
     * NonCredentialSchemaBuilder nonBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonBuilder.build();
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, true);
     *
     * int maxCredentials = 5;
     * boolean isDefault = false;
     * RevocationRegistryDefinition revocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
     *               credentialDefinition.getCredentialPublicKey(),
     *               maxCredentials,
     *               isDefault);
     *
     * SimpleTailsAccessor accessor = SimpleTailsAccessor.create(revocationRegistryDefinition.getRevocationTailsGenerator());
     * MasterSecret masterSecret = MasterSecret.create();
     *
     * CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
     * builder.addHidden("master_secret", masterSecret.ms);
     * builder.addKnown("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103");
     * CredentialValues credentialValues = return builder.build()
     *
     * BigInteger credentialNonce = BigNumber.random(LARGE_NONCE);
     * BlindedCredentials blindedCredentials = Prover.blindCredentialSecrets(
     *               credentialDefinition.getCredentialPublicKey(),
     *               credentialDefinition.getCredentialKeyCorrectnessProof(),
     *               credentialValues,
     *               credentialNonce);
     *
     * BigInteger issuanceNonce = BigNumber.random(LARGE_NONCE);
     *
     * int revocationIndex = 1;
     * SignedCredential signedCredential = Issuer.SignedCredential(
     *                 "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
     *                 blindedCredentials.getBlindedCredentialSecrets(),
     *                 blindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
     *                 credentialNonce,
     *                 issuanceNonce,
     *                 credentialValues,
     *                 credentialDefinition.getCredentialPublicKey(),
     *                 credentialDefinition.getCredentialPrivateKey());
     */
    public static SignedCredential signCredential(
            String prover_id,
            BlindedCredentialSecrets blindedCredentialSecrets,
            BlindedCredentialSecretsCorrectnessProof blindedCredentialSecretsCorrectnessProof,
            BigInteger credentialNonce,
            BigInteger credentialIssuanceNonce,
            CredentialValues credentialValues,
            CredentialPublicKey credentialPublicKey,
            CredentialPrivateKey credentialPrivateKey)
    {
        LOG.debug("Sign credential...");
        if(!BlindedCredentialSecretsCorrectnessProof.check(
                blindedCredentialSecrets,
                blindedCredentialSecretsCorrectnessProof,
                credentialNonce,
                credentialPublicKey.p_key))
        {
            LOG.error("Failed to check Blinded credential correctness proof");
            return null;
        }

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        BigInteger credentialContext = createCredentialContext(prover_id, null);

        PrimaryCredential primaryCredential = PrimaryCredential.create(
                credentialContext,
                credentialPublicKey,
                credentialPrivateKey,
                blindedCredentialSecrets,
                credentialValues);

        CredentialSignature credentialSignature = new CredentialSignature(primaryCredential.p_cred, null);

        SignatureCorrectnessProof signatureCorrectnessProof = SignatureCorrectnessProof.create(
                credentialPublicKey.p_key,
                credentialPrivateKey.p_key,
                credentialSignature.p_credential,
                primaryCredential.q,
                credentialIssuanceNonce);

        return new SignedCredential(credentialSignature, signatureCorrectnessProof, null);
    }

    /**
     * Signs credential values with primary keys and revocation
     *
     * @param prover_id
     * @param blindedCredentialSecrets
     * @param blindedCredentialSecretsCorrectnessProof
     * @param credentialNonce
     * @param credentialIssuanceNonce
     * @param credentialValues
     * @param credentialPublicKey
     * @param credentialPrivateKey
     * @param rev_idx
     * @param maxCredentials
     * @param isDefault
     * @param revocationRegistry
     * @param revocationPrivateKey
     * @param revocationTailsAccessor
     * @param <E>
     * @return <E extends RevocationTailsAccessor> SignedCredential
     * @throws CryptoException
     *
     * Example
     *
     * CredentialSchemaBuilder builder = CredentialSchema.CredentialSchemaBuilder().builder();
     * builder.addAttr("sex");
     * CredentialSchema credentialSchema = builder.build();
     *
     * NonCredentialSchemaBuilder nonBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonBuilder.build();
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, true);
     *
     * int maxCredentials = 5;
     * boolean isDefault = false;
     * RevocationRegistryDefinition revocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
     *               credentialDefinition.getCredentialPublicKey(),
     *               maxCredentials,
     *               isDefault);
     *
     * SimpleTailsAccessor accessor = SimpleTailsAccessor.create(revocationRegistryDefinition.getRevocationTailsGenerator());
     * MasterSecret masterSecret = MasterSecret.create();
     *
     * CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
     * builder.addHidden("master_secret", masterSecret.ms);
     * builder.addKnown("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103");
     * CredentialValues credentialValues = return builder.build()
     *
     * BigInteger credentialNonce = BigNumber.random(LARGE_NONCE);
     * BlindedCredentials blindedCredentials = Prover.blindCredentialSecrets(
     *               credentialDefinition.getCredentialPublicKey(),
     *               credentialDefinition.getCredentialKeyCorrectnessProof(),
     *               credentialValues,
     *               credentialNonce);
     *
     * BigInteger issuanceNonce = BigNumber.random(LARGE_NONCE);
     *
     * int revocationIndex = 1;
     * SignedCredential signedCredential = Issuer.signCredentialWithRevocation(
     *                 "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
     *                 blindedCredentials.getBlindedCredentialSecrets(),
     *                 blindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
     *                 credentialNonce,
     *                 issuanceNonce,
     *                 credentialValues,
     *                 credentialDefinition.getCredentialPublicKey(),
     *                 credentialDefinition.getCredentialPrivateKey(),
     *                 revocationIndex,
     *                 maxCredentials,
     *                 isDefault,
     *                 revocationRegistryDefinition.getRevocationRegistry(),
     *                 revocationRegistryDefinition.getRevocationPrivateKey(),
     *                 accessor);
     */
    public static <E extends RevocationTailsAccessor> SignedCredential signCredentialWithRevocation(
            String prover_id,
            BlindedCredentialSecrets blindedCredentialSecrets,
            BlindedCredentialSecretsCorrectnessProof blindedCredentialSecretsCorrectnessProof,
            BigInteger credentialNonce,
            BigInteger credentialIssuanceNonce,
            CredentialValues credentialValues,
            CredentialPublicKey credentialPublicKey,
            CredentialPrivateKey credentialPrivateKey,
            int rev_idx,
            int maxCredentials,
            boolean isDefault,
            RevocationRegistry revocationRegistry,
            RevocationPrivateKey revocationPrivateKey,
            E revocationTailsAccessor) throws CryptoException

    {
        LOG.debug("Sign credential with revocation...");
        if(!BlindedCredentialSecretsCorrectnessProof.check(
                blindedCredentialSecrets,
                blindedCredentialSecretsCorrectnessProof,
                credentialNonce,
                credentialPublicKey.p_key))
        {
            LOG.error("Failed to check Blinded credential correctness proof");
            return null;
        }

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        BigInteger credentialContext = createCredentialContext(prover_id, rev_idx);

        PrimaryCredential primaryCredential = PrimaryCredential.create(
                credentialContext,
                credentialPublicKey,
                credentialPrivateKey,
                blindedCredentialSecrets,
                credentialValues);

        NonRevocationCredential nonRevocationCredential = NonRevocationCredential.create(
                rev_idx,
                credentialContext,
                blindedCredentialSecrets,
                credentialPublicKey,
                credentialPrivateKey,
                maxCredentials,
                isDefault,
                revocationRegistry,
                revocationPrivateKey,
                revocationTailsAccessor);

        CredentialSignature credentialSignature = new CredentialSignature(
                primaryCredential.p_cred,
                nonRevocationCredential.nonRevocationCredentialSignature);

        SignatureCorrectnessProof signatureCorrectnessProof = SignatureCorrectnessProof.create(
                credentialPublicKey.p_key,
                credentialPrivateKey.p_key,
                credentialSignature.p_credential,
                primaryCredential.q,
                credentialIssuanceNonce);

        return new SignedCredential(
                credentialSignature,
                signatureCorrectnessProof,
                nonRevocationCredential.revocationRegistryDelta);
    }
}
