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

package org.iton.jssi.query;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class NotTest {

    @Test
    void Empty() throws JsonProcessingException {
        String query = "{\"$not\":{}}";
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Eq() throws JsonProcessingException {
        String query = String.format("{\"$not\":{\"%s\":\"%s\"}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Neq() throws JsonProcessingException {
        String query = String.format("{\"$not\":{\"%s\":{\"$neq\":\"%s\"}}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Gt() throws JsonProcessingException {
        String query = String.format("{\"$not\":{\"%s\":{\"$gt\":\"%s\"}}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Gte() throws JsonProcessingException {
        String query = String.format("{\"$not\":{\"%s\":{\"$gte\":\"%s\"}}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Lt() throws JsonProcessingException {
        String query = String.format("{\"$not\":{\"%s\":{\"$lt\":\"%s\"}}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Lte() throws JsonProcessingException {
        String query = String.format("{\"$not\":{\"%s\":{\"$lte\":\"%s\"}}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Like() throws JsonProcessingException {
        String query = String.format("{\"$not\":{\"%s\":{\"$like\":\"%s\"}}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void SingleNotIn() throws JsonProcessingException {
        String query = String.format("{\"$not\":[{\"%s\":{\"$in\":[\"%s\"]}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Mixed() throws JsonProcessingException {
        String query = String.format("{\"$not\":{\"$and\":[{\"%s\":\"%s\"},{\"$or\":[{\"%s\":{\"$gt\":\"%s\"}},{\"$not\":{\"%s\":{\"$lte\":\"%s\"}}},{\"$and\":[{\"%s\":{\"$lt\":\"%s\"}},{\"$not\":{\"%s\":{\"$gte\":\"%s\"}}}]}]},{\"$not\":{\"%s\":{\"$like\":\"%s\"}}},{\"$and\":[{\"%s\":\"%s\"},{\"$not\":{\"%s\":{\"$neq\":\"%s\"}}}]}]}}",
                "name1", "value1",
                "name2", "value2",
                "name3", "value3",
                "name4", "value4",
                "name5", "value5",
                "name6", "value6",
                "name7", "value7",
                "name8", "value8");
        Query result = Query.build(query);
        assertEquals(query, result.toString());
    }

}