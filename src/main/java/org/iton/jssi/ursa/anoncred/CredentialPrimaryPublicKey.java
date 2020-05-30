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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;

import java.math.BigInteger;
import java.util.Map;

/**
 * Issuer's "Public Key" is used to verify the Issuer's signature over the Credential's attributes' values (primary credential).
 */
public class CredentialPrimaryPublicKey {

    @JsonProperty("n")
    public BigInteger n;
    @JsonProperty("s")
    public BigInteger s;
    @JsonProperty("r")
    public Map<String, BigInteger> r;
    @JsonProperty("rctxt")
    public BigInteger rctxt;
    @JsonProperty("z")
    public BigInteger z;

    @JsonCreator
    public CredentialPrimaryPublicKey(@JsonProperty("n") BigInteger n,
                                      @JsonProperty("s") BigInteger s,
                                      @JsonProperty("rctxt") BigInteger rctxt,
                                      @JsonProperty("r") Map<String, BigInteger> r,
                                      @JsonProperty("z") BigInteger z){
        this.n = n;
        this.s = s;
        this.r = r;
        this.rctxt = rctxt;
        this.z = z;
    }
}
