/*
 * The MIT License
 *
 * Copyright 2019 ITON Solutions.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.iton.jssi.ursa.bls;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.iton.jssi.ursa.pair.CryptoException;
import org.iton.jssi.ursa.pair.Pair;
import org.iton.jssi.ursa.pair.PointG1;
import org.iton.jssi.ursa.pair.PointG2;
import org.iton.jssi.ursa.util.Keccak256;

/**
 *
 * @author ITON Solutions
 */
public class BLS {
    
    /** 
     * Signs the message and returns signature.
     *
     * # Arguments
     *
     * message - Message to sign
     * signKey - Sign key
     *
     * Example
     *
     * 
     * byte[] message = new byte[]{1, 2, 3, 4, 5};
     * SignKey signKey = new SignKey(null);
     * sign(message, signKey);
     *
     * @param message
     * @param signKey
     * @return 
     */
    
    public static Signature sign(byte[] message, SignKey signKey) {
        
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            PointG1 point = genSignature(message, signKey, digest);
            return new Signature(point);
        }catch(CryptoException | NoSuchAlgorithmException e ){}
        
        return null;
    }
    
    /**
     * Verifies the message signature and returns true - if signature valid or false otherwise
     * 
     * @param signature
     * @param message
     * @param verKey
     * @param gen
     * @return boolean
     */
    public static boolean verify(Signature signature, byte[] message, VerKey verKey, Generator gen) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return verifySignature(signature.point, message, verKey.point, gen, digest);
        } catch (CryptoException | NoSuchAlgorithmException e) {
            return false;
        }
    }
    
    public static boolean verifyMultiSignature(MultiSignature multi_sig, byte[] message, VerKey[] verKeys, Generator gen) {
        // Since each signer (identified by a Verkey) has signed the same message, the public keys
        // can be added together to form the aggregated verkey
        PointG2 aggregatedVerkey = PointG2.infinity();
        for(VerKey ver_key : verKeys) {
            aggregatedVerkey = aggregatedVerkey.add(ver_key.point);
        }

        // TODO: Add a new method that takes a message and an aggregated verkey and expose using
        // the C API. Verifiers can thus cache the aggregated verkey and avoid several EC point additions.
        // The code below should be moved to such method.
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return verifySignature(multi_sig.point, message, aggregatedVerkey, gen, digest);
        } catch (CryptoException | NoSuchAlgorithmException e) {
            return false;
        }
    }
    
    public static boolean verifyProofOfPossession(ProofOfPossession pop, VerKey verKey, Generator gen) {
        Keccak256 digest = new Keccak256();
        try {
            return verifySignature(pop.point, verKey.bytes, verKey.point, gen, digest);
        } catch (CryptoException e) {
            return false;
        }
    }
    
    private static boolean verifySignature(PointG1 signature, byte[] message, PointG2 verKey, Generator gen, MessageDigest digest) throws CryptoException {
        PointG1 point = hash(message, digest);
        return Pair.pair(signature, gen.point).equals(Pair.pair(point, verKey));
    }
    
    private static boolean verifySignature(PointG1 signature, byte[] message, PointG2 verKey, Generator gen, Keccak256 digest) throws CryptoException {
        PointG1 hash = keccak(message, digest);
        return Pair.pair(signature, gen.point).equals(Pair.pair(hash, verKey));
    }
    
    public static PointG1 genSignature(byte[] message, SignKey signKey, MessageDigest digest) throws CryptoException {
        return hash(message, digest).mul(signKey.groupOrderElement);
    }
    
    public static PointG1 genSignature(byte[] message, SignKey signKey, Keccak256 digest) throws CryptoException {
        return keccak(message, digest).mul(signKey.groupOrderElement);
    }
    
    private static PointG1 hash(byte[] message, MessageDigest digest) throws CryptoException{
        byte[] hash = digest.digest(message);
        return new PointG1().fromHash(hash);
    }
    
    private static PointG1 keccak(byte[] message, Keccak256 digest) throws CryptoException{
        byte[] hash = digest.digest(message);
        return new PointG1().fromHash(hash);
    }
    
}
