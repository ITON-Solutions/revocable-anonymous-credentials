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

import java.util.ArrayList;
import java.util.List;

public class SubProofRequest {

    public List<String> revealed_attrs;
    public List<Predicate>  predicates;

    private SubProofRequest(List<String> revealed_attr, List<Predicate>  predicates){
        this.revealed_attrs = revealed_attr;
        this.predicates = predicates;
    }

    public static SubProofRequestBuilder builder(){
        return new SubProofRequestBuilder();
    }

    public static class SubProofRequestBuilder{

        private List<String> revealed_attrs = new ArrayList<>();
        private List<Predicate>  predicates = new ArrayList<>();

        public void addRevealedAttr(String attr) {
            revealed_attrs.add(attr);
        }

        public void addPredicate(String attr_name, String p_type, int value) {

            PredicateType predicateType;
            switch (p_type){
                case "GE":
                    predicateType = PredicateType.GE;
                    break;
                case "LE":
                    predicateType = PredicateType.LE;
                    break;
                case "GT":
                    predicateType = PredicateType.GT;
                    break;
                case "LT":
                    predicateType = PredicateType.LT;
                    break;
                default:
                    predicateType = PredicateType.UNKNOWN;
            }

            Predicate predicate = new Predicate(attr_name, predicateType, value);
            predicates.add(predicate);
        }

        public SubProofRequest build(){
            return new SubProofRequest(revealed_attrs, predicates);
        }
    }
}
