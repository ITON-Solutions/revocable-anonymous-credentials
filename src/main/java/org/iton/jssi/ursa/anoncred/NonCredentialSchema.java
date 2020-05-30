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
package org.iton.jssi.ursa.anoncred;

import java.util.ArrayList;
import java.util.List;

public class NonCredentialSchema {

    public List<String> attrs;

    private NonCredentialSchema(List<String> attrs){
        this.attrs = attrs;
    }

    public static NonCredentialSchemaBuilder builder(){
        return new NonCredentialSchemaBuilder();
    }

    /**
     * Creates and returns credential schema entity builder
     *
     * Example
     *
     * NonCredentialSchemaBuilder builder = NonCredentialSchema.builder();
     * builder.addAttr("sex");
     * builder.addAttr("name");
     * NonCredentialSchema schema = builder.build();
     */
    public static class NonCredentialSchemaBuilder{
        List<String> attrs = new ArrayList<>();

        public NonCredentialSchemaBuilder addAttr(String attr){
            attrs.add(attr);
            return this;
        }

        public NonCredentialSchema build(){
            return new NonCredentialSchema(attrs);
        }
    }
}
