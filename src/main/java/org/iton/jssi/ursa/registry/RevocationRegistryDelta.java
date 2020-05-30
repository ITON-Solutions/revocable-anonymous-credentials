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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/// `Revocation Registry Delta` contains Accumulator changes.
/// Must be applied to `Revocation Registry`
public class RevocationRegistryDelta {

    private static final Logger LOG = LoggerFactory.getLogger(RevocationRegistryDelta.class);

    Accumulator previous;
    Accumulator accumulator;
    List<Integer> issued;
    List<Integer> revoked;

    public RevocationRegistryDelta(Accumulator previous,
                                   Accumulator accumulator,
                                   List<Integer> issued,
                                   List<Integer> revoked) {
        this.previous = previous;
        this.accumulator = accumulator;
        this.issued = issued;
        this.revoked = revoked;

    }

    public static RevocationRegistryDelta fromParts(
            RevocationRegistry revocationRegistryFrom,
            RevocationRegistry revocationRegistryTo,
            List<Integer> issued,
            List<Integer> revoked) {

        return new RevocationRegistryDelta(revocationRegistryFrom == null ? null : revocationRegistryFrom.accumulator,
                revocationRegistryTo.accumulator,
                issued,
                revoked);
    }

    public void merge(RevocationRegistryDelta delta) {
        if (delta.previous == null || accumulator != delta.previous) {
            LOG.error("Deltas can not be merged.");
            return;
        }

        accumulator = delta.accumulator;

        issued.removeAll(delta.revoked);
        issued.addAll(delta.issued);
        issued = issued.stream().distinct().collect(Collectors.toList());

        revoked.removeAll(delta.issued);
        revoked.addAll(delta.revoked);
        revoked = revoked.stream().distinct().collect(Collectors.toList());
    }
}
