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

import org.iton.jssi.ursa.anoncred.util.BigNumber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

import static org.iton.jssi.ursa.anoncred.util.BigNumber.*;

public class PrimaryCredential {

    private static final Logger LOG = LoggerFactory.getLogger(PrimaryCredential.class);

    public PrimaryCredentialSignature p_cred;
    public BigInteger q;

    public PrimaryCredential(PrimaryCredentialSignature p_cred, BigInteger q){
        this.p_cred = p_cred;
        this.q = q;
    }

    public static PrimaryCredential create(
            BigInteger credentialContext,
            CredentialPublicKey credentialPublicKey,
            CredentialPrivateKey credentialPrivateKey,
            BlindedCredentialSecrets blindedCredentialSecrets,
            CredentialValues credentialValues)
    {
        LOG.debug("Create Primary credential...");
        BigInteger v = random(LARGE_VPRIME_PRIME).or(LARGE_VPRIME_PRIME_VALUE);
        v = new BigInteger("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027", 10);
        BigInteger e = BigNumber.primeInRange(LARGE_E_START_VALUE, LARGE_E_END_RANGE_VALUE);
        e = new BigInteger("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930201588264091397308910346117473868881", 10);

        SignedPrimaryCredential signedPrimaryCredential = SignedPrimaryCredential.create(
                credentialPublicKey,
                credentialPrivateKey,
                credentialContext,
                credentialValues,
                v,
                blindedCredentialSecrets,
                e);

        PrimaryCredentialSignature primaryCredentialSignature = new PrimaryCredentialSignature(credentialContext, signedPrimaryCredential.a, e, v);
        return new PrimaryCredential(primaryCredentialSignature, signedPrimaryCredential.q);
    }
}
