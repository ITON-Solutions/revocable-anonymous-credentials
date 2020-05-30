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

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.iton.jssi.ursa.anoncred.CredentialValue.Type.HIDDEN;
import static org.iton.jssi.ursa.anoncred.CredentialValue.Type.KNOWN;

/// represents credential attributes values map.
///
// # Example
/// ```
///
/// CredentialValuesBuilder builder = CredentialValues.builder();
/// builder.addKnown("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103");
/// builder.addKnown("name", "1139481716457488690172217916278103335");
/// CredentialValues values = builder.build();
/// ```
public class CredentialValues {

    private final Map<String, CredentialValue> values;

    private CredentialValues(Map<String, CredentialValue> values){
        this.values = values;
    }

    public static CredentialValuesBuilder builder(){
        return new CredentialValuesBuilder();
    }

    public static class CredentialValuesBuilder {

        Map<String, CredentialValue> values = new LinkedHashMap<>();

        public void addKnown(String name, BigInteger value){
            values.put(name, new CredentialValue(KNOWN, value));
        }

        public void addKnown(String name, String value){
            values.put(name, new CredentialValue(KNOWN, new BigInteger(value, 10)));
        }

        public void addHidden(String name, BigInteger value){
            values.put(name, new CredentialValue(HIDDEN, value));
        }

        public void addHidden(String name, String value){
            values.put(name, new CredentialValue(HIDDEN, new BigInteger(value, 10)));
        }

        public void addCommitment(String name, BigInteger value, BigInteger blinding){
            values.put(name, new CredentialValue(HIDDEN, value, blinding));
        }

        public void addCommitment(String name, String value, String blinding){
            values.put(name, new CredentialValue(HIDDEN, new BigInteger(value, 10), new BigInteger(blinding, 10)));
        }

        public CredentialValues build(){
            return new CredentialValues(values);
        }
    }

    public Map<String, CredentialValue> getValues() {
        return values;
    }
}
