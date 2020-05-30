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

class OrTest {

    @Test
    void Empty() throws JsonProcessingException {
        String query = "{\"$or\":[]}";
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Eq() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":\"%s\"}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Neq() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$neq\":\"%s\"}}]}", "name", "value");
        Query result =  Query.build(query);
        assertEquals(query, result.toString());
    }

    @Test
    void Gt() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$gt\":\"%s\"}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Gte() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$gte\":\"%s\"}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Lt() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$lt\":\"%s\"}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Lte() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$lte\":\"%s\"}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Like() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$like\":\"%s\"}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void SingleIn() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$in\":[\"%s\"]}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListNot() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"$not\":{\"%s\":\"%s\"}},{\"$not\":{\"%s\":\"%s\"}},{\"$not\":{\"%s\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        Query result =  Query.build(query);
        assertEquals(query, result.toString());
    }

    @Test
    void SingleNot() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"$not\":{\"%s\":\"%s\"}}]}", "name1", "value1");
        Query result =  Query.build(query);
        assertEquals(query, result.toString());
    }

    @Test
    void ListEq() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":\"%s\"},{\"%s\":\"%s\"},{\"%s\":\"%s\"}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListNeq() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$neq\":\"%s\"}},{\"%s\":{\"$neq\":\"%s\"}},{\"%s\":{\"$neq\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListGt() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$gt\":\"%s\"}},{\"%s\":{\"$gt\":\"%s\"}},{\"%s\":{\"$gt\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListGte() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$gte\":\"%s\"}},{\"%s\":{\"$gte\":\"%s\"}},{\"%s\":{\"$gte\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListLt() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$lt\":\"%s\"}},{\"%s\":{\"$lt\":\"%s\"}},{\"%s\":{\"$lt\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListLte() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$lte\":\"%s\"}},{\"%s\":{\"$lte\":\"%s\"}},{\"%s\":{\"$lte\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListLike() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$like\":\"%s\"}},{\"%s\":{\"$like\":\"%s\"}},{\"%s\":{\"$like\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListIn() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$in\":[\"%s\"]}},{\"%s\":{\"$in\":[\"%s\"]}},{\"%s\":{\"$in\":[\"%s\"]}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        Query result =  Query.build(query);
        assertEquals(query, result.toString());
    }

    @Test
    void Mixed() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":\"%s\"},{\"%s\":{\"$neq\":\"%s\"}},{\"%s\":{\"$gt\":\"%s\"}},{\"%s\":{\"$gte\":\"%s\"}},{\"%s\":{\"$lt\":\"%s\"}},{\"%s\":{\"$lte\":\"%s\"}},{\"%s\":{\"$like\":\"%s\"}},{\"%s\":{\"$in\":[\"%s\",\"%s\"]}},{\"$not\":{\"%s\":\"%s\"}}]}",
                "name1", "value1",
                "name2", "value2",
                "name3", "value3",
                "name4", "value4",
                "name5", "value5",
                "name6", "value6",
                "name7", "value7",
                "name8", "value8a", "value8b",
                "name9", "value9");
        Query result = Query.build(query);
        assertEquals(query, result.toString());
    }


}