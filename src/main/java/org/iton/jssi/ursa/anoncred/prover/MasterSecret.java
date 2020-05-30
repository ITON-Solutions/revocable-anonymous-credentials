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

package org.iton.jssi.ursa.anoncred.prover;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import org.iton.jssi.ursa.anoncred.util.BigNumber;

import java.math.BigInteger;

import static org.iton.jssi.ursa.anoncred.util.BigNumber.LARGE_MASTER_SECRET;



/**
 * Secret key encoded in a credential that is used to prove that prover owns the credential; can be used to
 * prove linkage across credentials.
 * Prover blinds master secret, generating BlindedCredentialSecrets and CredentialSecretsBlindingFactors (blinding factors)
 * and sends the BlindedCredentialSecrets to Issuer who then encodes it credential creation.
 * The blinding factors are used by Prover for post processing of issued credentials.
 */
public class MasterSecret {
    @JsonSerialize(using = ToStringSerializer.class) public BigInteger ms;

    @JsonCreator
    public MasterSecret(@JsonProperty("value") BigInteger ms){
        this.ms = ms;
    }

     public static MasterSecret create(){
        BigInteger ms = BigNumber.random(LARGE_MASTER_SECRET);
        ms = new BigInteger("21578029250517794450984707538122537192839006240802068037273983354680998203845", 10);
        return new MasterSecret(ms);
    }
}
