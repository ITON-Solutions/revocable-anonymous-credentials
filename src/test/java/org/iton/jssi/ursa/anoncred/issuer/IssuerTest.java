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
import org.iton.jssi.ursa.anoncred.prover.Prover;
import org.iton.jssi.ursa.anoncred.prover.ProverEmulator;
import org.iton.jssi.ursa.anoncred.util.BigNumber;
import org.iton.jssi.ursa.anoncred.util.Helper;
import org.iton.jssi.ursa.pair.CryptoException;
import org.iton.jssi.ursa.registry.RevocationRegistry;
import org.iton.jssi.ursa.registry.RevocationRegistryDefinition;
import org.iton.jssi.ursa.util.Bytes;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;
import static org.junit.jupiter.api.Assertions.*;

class IssuerTest {

    IssuerEmulator issuer = new IssuerEmulator();
    ProverEmulator prover = new ProverEmulator();


    @Test
    void credentialSchemaBuilder() {
        CredentialSchema.CredentialSchemaBuilder builder = CredentialSchema.builder();
        builder.addAttr("sex");
        builder.addAttr("name");
        builder.addAttr("age");
        CredentialSchema schema = builder.build();

        assertTrue(schema.attrs.contains("sex"));
        assertTrue(schema.attrs.contains("name"));
        assertTrue(schema.attrs.contains("age"));
        assertFalse(schema.attrs.contains("height"));
    }

    @Test
    void credentialValuesBuilder() {
        CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
        builder.addKnown("sex", "89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129");
        builder.addKnown("name", "58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471");
        CredentialValues values = builder.build();

        CredentialValue sex = new CredentialValue(CredentialValue.Type.KNOWN, new BigInteger("89057765651800459030103911598694169835931320404459570102253965466045532669865684092518362135930940112502263498496335250135601124519172068317163741086983519494043168252186111551835366571584950296764626458785776311514968350600732183408950813066589742888246925358509482561838243805468775416479523402043160919428168650069477488093758569936116799246881809224343325540306266957664475026390533069487455816053169001876208052109360113102565642529699056163373190930839656498261278601357214695582219007449398650197048218304260447909283768896882743373383452996855450316360259637079070460616248922547314789644935074980711243164129", 10));
        CredentialValue name = new CredentialValue(CredentialValue.Type.KNOWN, new BigInteger("58606710922154038918005745652863947546479611221487923871520854046018234465128105585608812090213473225037875788462225679336791123783441657062831589984290779844020407065450830035885267846722229953206567087435754612694085258455822926492275621650532276267042885213400704012011608869094703483233081911010530256094461587809601298503874283124334225428746479707531278882536314925285434699376158578239556590141035593717362562548075653598376080466948478266094753818404986494459240364648986755479857098110402626477624280802323635285059064580583239726433768663879431610261724430965980430886959304486699145098822052003020688956471", 10));

        assertEquals(values.getValues().get("sex"), sex);
        assertEquals(values.getValues().get("name"), name);
        assertNull(values.getValues().get("age"));
    }

    @Test
    void createCredentialContext() {
        int rev_idx = 110;
        String user_id = "111";
        BigInteger answer = new BigInteger("31894574610223295263712513093148707509913459424901632064286025736442349335521", 10);
        BigInteger result = Issuer.createCredentialContext(user_id, rev_idx);
        assertEquals(result, answer);
    }

    @Test
    void createCredentialPrimaryKeys(){
    }

    @Test
    void createCredentialKeyCorrectnessProof() {

        CredentialPrimaryPublicKey credentialPrimaryPublicKey = issuer.getCredentialPrimaryPublicKey();
        CredentialPrimaryPrivateKey credentialPrimaryPrivateKey = issuer.getCredentialPrimaryPrivateKey();
        BigInteger n = credentialPrimaryPublicKey.n;
        BigInteger s = credentialPrimaryPublicKey.s;
        BigInteger x = BigNumber.genX(credentialPrimaryPrivateKey.p, credentialPrimaryPrivateKey.q);
        BigInteger z = s.modPow(x, n);

        BigInteger x_tilde = BigNumber.genX(credentialPrimaryPrivateKey.p, credentialPrimaryPrivateKey.q);
        BigInteger z_tilde = s.modPow(x_tilde, n);
        byte[] hash = Helper.hash(Bytes.concat(asUnsignedByteArray(z), asUnsignedByteArray(z_tilde)));
        BigInteger c = new BigInteger(1, hash);
        BigInteger x_cap = x_tilde.add(x.multiply(c));

        BigInteger z_inverse = z.modInverse(n);
        BigInteger z_cap_result = Helper.getPedersenCommitment(
                z_inverse,
                c,
                s,
                x_cap,
                n);

        byte[] hash_result = Helper.hash(Bytes.concat(asUnsignedByteArray(z), asUnsignedByteArray(z_cap_result)));
        assertArrayEquals(hash, hash_result);
    }

    @Test
    void createCredentialDefinition() {

        CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(
                issuer.getCredentialSchema(),
                issuer.getNonCredentialSchema(),
                true);
        assertNotNull(credentialDefinition);

        boolean result = CredentialKeyCorrectnessProof.check(
                credentialDefinition.getCredentialPublicKey().p_key,
                credentialDefinition.getCredentialKeyCorrectnessProof());
        assertTrue(result);

        credentialDefinition = Issuer.createCredentialDefinition(
                issuer.getCredentialSchema(),
                issuer.getNonCredentialSchema(),
                false);
        assertNotNull(credentialDefinition);

        result = CredentialKeyCorrectnessProof.check(
                credentialDefinition.getCredentialPublicKey().p_key,
                credentialDefinition.getCredentialKeyCorrectnessProof());
        assertTrue(result);
    }

    @Test
    void createCredentialDefinitionWithoutRevocation() {

        CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(
                issuer.getCredentialSchema(),
                issuer.getNonCredentialSchema(),
                false);
        assertNotNull(credentialDefinition);

        boolean result = CredentialKeyCorrectnessProof.check(
                credentialDefinition.getCredentialPublicKey().p_key,
                credentialDefinition.getCredentialKeyCorrectnessProof());
        assertTrue(result);
    }

    @Test
    void createRevocationRegistry() {
        RevocationRegistry revocationRegistry = issuer.getRevocationRegistry();
        assertNotNull(revocationRegistry);
    }

    @Test
    void createRevocationRegistryDefinition() throws CryptoException {
        RevocationRegistryDefinition revocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
                issuer.getCredentialPublicKey(),
                10,
                true);
        assertNotNull(revocationRegistryDefinition);
    }

    @Test
    void checkBlindedCredentialSecretsCorrectnessProof(){
        CredentialPublicKey credentialPublicKey = issuer.getCredentialPublicKey();
        CredentialKeyCorrectnessProof credentialKeyCorrectnessProof = issuer.getCredentialKeyCorrectnessProof();
        CredentialValues credentialValues = issuer.getCredentialValues();
        BigInteger nonce = issuer.getCredentialNonce();

        BlindedCredentials blindedCredentials = Prover.blindCredentialSecrets(
                credentialPublicKey,
                credentialKeyCorrectnessProof,
                credentialValues,
                nonce);

        boolean result = BlindedCredentialSecretsCorrectnessProof.check(
                blindedCredentials.getBlindedCredentialSecrets(),
                blindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
                nonce,
                credentialPublicKey.p_key);

        assertTrue(result);
    }

    @Test
    void signCredential() throws CryptoException {

        CredentialPublicKey credentialPublicKey = issuer.getCredentialPublicKey();
        CredentialPrivateKey credentialPrivateKey = issuer.getCredentialPrivateKey();
        BigInteger credentialNonce = issuer.getCredentialNonce();

        BlindedCredentialSecrets blindedCredentialSecrets = prover.getBlindedCredentialSecrets();
        BlindedCredentialSecretsCorrectnessProof blindedCredentialSecretsCorrectnessProof = prover.getBlindedCredentialSecretsCorrectnessProof();

        BigInteger issuanceNonce = issuer.getCredentialIssuanceNonce();

        SignedCredential signedCredential = Issuer.signCredential(
                prover.PROVER_DID,
                blindedCredentialSecrets,
                blindedCredentialSecretsCorrectnessProof,
                credentialNonce,
                issuanceNonce,
                issuer.getCredentialValues(),
                credentialPublicKey,
                credentialPrivateKey);

        assertNotNull(signedCredential);
        assertEquals(signedCredential.signatureCorrectnessProof.c, new BigInteger("104614497723451518313474575657334201988423454698609284842270966472600991936715", 10));
        assertEquals(signedCredential.signatureCorrectnessProof.se, new BigInteger("2316535684685338402719486099497140440509397138514378133900918780469333389486480136191111850166211328850132141833185838701387786377623699701658879707418243873469067338140105909353701983443961216560305099507619894326327011215343831546393461935652727353729569211077678341251559194609266655606583044286237683570733202945212568927881569396756593635310226246775751361393857771145736904040474358059868319224376073326444256671202625371892195787938290235698138706566228735474013375599813867888682764948153638492162885537864183419476303364006809656184241492423118811158508955306092796494765272630456714671171097052765655820709", 10));
    }

    @Test
    void signPrimaryCredential() throws CryptoException {
        CredentialPublicKey pub_key = issuer.getCredentialPublicKey();
        CredentialPrivateKey secret_key = issuer.getCredentialPrivateKey();

        BigInteger context_attribute = issuer.m2();

        CredentialValues credential_values = issuer.getCredentialValues();
        PrimaryCredentialSignature primary_credential = issuer.getPrimaryCredentialSignature();

        SignedPrimaryCredential signedPrimaryCredential = SignedPrimaryCredential.create(
                pub_key,
                secret_key,
                context_attribute,
                credential_values,
                primary_credential.v,
                prover.getBlindedCredentialSecrets(),
                primary_credential.e);

        BigInteger expected_q = primary_credential.a.modPow(primary_credential.e, pub_key.p_key.n);
        assertNotNull(signedPrimaryCredential);
        assertEquals(expected_q, signedPrimaryCredential.q);
        assertEquals(primary_credential.a, signedPrimaryCredential.a);
    }
}