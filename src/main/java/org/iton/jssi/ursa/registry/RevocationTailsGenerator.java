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

package org.iton.jssi.ursa.registry;

import org.iton.jssi.ursa.pair.GroupOrderElement;
import org.iton.jssi.ursa.pair.PointG2;

public class RevocationTailsGenerator {

    private int size;
    private int current_index;
    private PointG2 g_dash;
    private GroupOrderElement gamma;

    public RevocationTailsGenerator(int maxCredentials, GroupOrderElement gamma, PointG2 g_dash){
        this.size = 2 * maxCredentials + 1; /* Unused 0th + valuable 1..L + unused (L+1)th + valuable (L+2)..(2L) */
        this.current_index = 0;
        this.gamma = gamma;
        this.g_dash = g_dash;
    }

    public int count() {
         return size - current_index;
    }

    public Tail next() {
        if (current_index >= size) {
            return null;
        }

        Tail tail = Tail.create(current_index, g_dash, gamma);
        current_index += 1;
        return tail;
    }
}
