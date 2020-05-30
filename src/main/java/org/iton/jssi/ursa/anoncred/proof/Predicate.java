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

package org.iton.jssi.ursa.anoncred.proof;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.math.BigInteger;

public class Predicate {

    String attr_name;
    PredicateType p_type;
    int value;

    @JsonCreator
    public Predicate(
            @JsonProperty("attr_name") String attr_name,
            @JsonProperty("p_type") PredicateType p_type,
            @JsonProperty("value") int value){
        this.attr_name = attr_name;
        this.p_type = p_type;
        this.value = value;
    }

    public int getDelta(int attr_value) {

        switch (p_type){
            case GE:
                return attr_value - this.value;
            case GT:
                return attr_value - this.value - 1;
            case LE:
                return this.value - attr_value;
            case LT:
                return this.value - attr_value - 1;
        }

        return 0;
    }

    public BigInteger getDeltaPrime(){
        switch (p_type){
            case GE:
            case LE:
                return BigInteger.valueOf(this.value);
            case GT:
                return BigInteger.valueOf(this.value + 1);
            case LT:
                return BigInteger.valueOf(this.value - 1);
        }

        return BigInteger.ZERO;
    }

    public boolean isLess(){
        switch (p_type){
            case GE:
            case GT:
                return false;
            default:
                return true;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Predicate predicate = (Predicate) o;

        if (value != predicate.value) return false;
        if (!attr_name.equals(predicate.attr_name)) return false;
        return p_type == predicate.p_type;
    }
}
