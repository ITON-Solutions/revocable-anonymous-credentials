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
import org.iton.jssi.ursa.anoncred.CredentialPrimaryPublicKey;
import org.iton.jssi.ursa.anoncred.issuer.IssuerEmulator;
import org.iton.jssi.ursa.anoncred.proof.PrimaryEqualProof;
import org.iton.jssi.ursa.anoncred.proof.PrimaryPredicateInequalityProof;
import org.iton.jssi.ursa.anoncred.proof.SubProofRequest;
import org.iton.jssi.ursa.anoncred.prover.ProverEmulator;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ProofVerifierTest {

    ProverEmulator prover = new ProverEmulator();
    IssuerEmulator issuer = new IssuerEmulator();

    @Test
    void verifyEq() {

        PrimaryEqualProof proof = prover.getPrimaryEqProof();
        CredentialPrimaryPublicKey credentialPrimaryPublicKey = issuer.getCredentialPrimaryPublicKey();
        BigInteger c_hash = prover.getAggregatedProof().c_hash;
        CredentialSchema credentialSchema = issuer.getCredentialSchema();
        NonCredentialSchema nonCredentialSchema = issuer.getNonCredentialSchema();

        SubProofRequest.SubProofRequestBuilder builder = SubProofRequest.builder();
        builder.addRevealedAttr("name");
        SubProofRequest subProofRequest = builder.build();

        List<BigInteger> res = ProofVerifier.verifyEq(
                credentialPrimaryPublicKey,
                proof,
                c_hash,
                credentialSchema,
                nonCredentialSchema,
                subProofRequest);

        assertEquals("10403187904873314760355557832761590691431383521745031865309573910963034393207684" +
        "41047372720051528347747837647360259125725910627967862485202935551931564829193622679374932738" +
        "38474536597850351434049013891806846939373481702013509894344027659392557687896251802916259781" +
        "84555673228742169810564578048461551461925810052930346018787363753466820600660809185539201223" +
        "71561407375323615559370420617674817058682033406887804922024342182995444044012636448897449995" +
        "96623718830501291018016504024850859488898905605533676936340030965601041522317339491952524844" +
        "02507347769428679283112853202405399796966635008669186194259851326316679551259", res.get(0).toString());
    }

    @Test
    public void verifyNePredicate() {

        PrimaryPredicateInequalityProof proof = prover.getPrimaryPredicateNeProof();
        BigInteger c_hash = prover.getAggregatedProof().c_hash;
        CredentialPrimaryPublicKey credentialPrimaryPublicKey = issuer.getCredentialPrimaryPublicKey();

        List<BigInteger> res = ProofVerifier.verifyNePredicate(credentialPrimaryPublicKey, proof, c_hash);

        assertNotNull(res);

        assertEquals("84541983257221862363846490076513159323178083291858042421207690118109227097470776" +
        "29156584847233795772635909150135300090254032895037949890518860393886507672431721432085454991" +
        "53093207263594616249619617338381693555232209880961750666056680810026822527599168269456730020" +
        "01231825064670095844788135102734720995698848664953286323041296412437988472201525915887801570" +
        "70103470323302606738147041031249783093273756323937754190996658020897337906239502331775611703" +
        "28042970307095658890209337238786401127759306357959942690001365403300148843097814151882478353" +
        "39418932462384016593481929101948092657508460688911105398322543841514412679282",  res.get(0).toString());

        assertEquals("84541983257221862363846490076513159323178083291858042421207690118109227097470776" +
        "29156584847233795772635909150135300090254032895037949890518860393886507672431721432085454991" +
        "53093207263594616249619617338381693555232209880961750666056680810026822527599168269456730020" +
        "01231825064670095844788135102734720995698848664953286323041296412437988472201525915887801570" +
        "70103470323302606738147041031249783093273756323937754190996658020897337906239502331775611703" +
        "28042970307095658890209337238786401127759306357959942690001365403300148843097814151882478353" +
        "39418932462384016593481929101948092657508460688911105398322543841514412679282",  res.get(4).toString());

        assertEquals("71576740094469616050175125038612941221466947853166771156257978699698137573095744" +
        "20081189100581220746619329202518959516574932458476055705176224361367551303754232635252988973" +
        "23789904575729089031680343784068658206913548928748946934732765157510452464211110112604384315" +
        "16865750528792129415255282372242857723274819466930397323134722222564785435619193280367926994" +
        "59191029832881324878202293930994818463297709055310139101500199217390179488337854210925404890" +
        "00403016403129020563799240705009712476150627783447048219852434435047969447195784507059403459" +
        "40533745092900800249667587825786217899894277583562804465078452786585349967293",  res.get(5).toString());
    }
}