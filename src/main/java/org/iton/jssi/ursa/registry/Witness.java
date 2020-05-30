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

import org.iton.jssi.ursa.pair.PointG2;

import java.util.ArrayList;
import java.util.List;

public class Witness {

    public PointG2 omega;

    private Witness(PointG2 omega){
        this.omega = omega;
    }

    public static <E extends RevocationTailsAccessor> Witness create(
            int revocationIndex,
            int maxCredentials,
            boolean isDefault,
            RevocationRegistryDelta revocationRegistryDelta,
            E revocationTailsAccessor)
    {
        PointG2 omega = PointG2.infinity();
        List<Integer> issued = new ArrayList<>();

        if(isDefault){
            for(int i = 1; i < maxCredentials + 1; i++){
                issued.add(i);
            }
            // TODO
            if(revocationRegistryDelta != null) {
                for (int j : revocationRegistryDelta.revoked) {
                    issued.remove(Integer.valueOf(j));
                }
            }
        } else {
            issued.addAll(revocationRegistryDelta.issued);
        }

        issued.remove(Integer.valueOf(revocationIndex));

        for(int j : issued) {
            int index = maxCredentials + 1 - j + revocationIndex;
            Tail tail = revocationTailsAccessor.access(index);
            omega = omega.add(tail);
        }
        return new Witness(omega);
    }

    public <E extends RevocationTailsAccessor> void update(
            int revocationIndex,
            int maxCredentials,
            RevocationRegistryDelta revocationRegistryDelta,
            E revocationTailsAccessor)
    {
        PointG2 omega_denom = PointG2.infinity();
        for (int j : revocationRegistryDelta.revoked) {
            if (revocationIndex == j) {
                continue;
            }

            int index = maxCredentials + 1 - j + revocationIndex;
            Tail tail = revocationTailsAccessor.access(index);
            omega_denom = omega_denom.add(tail);
        }

        PointG2 omega_num = PointG2.infinity();
        for (int j : revocationRegistryDelta.issued) {
            if (revocationIndex == j) {
                continue;
            }

            int index = maxCredentials + 1 - j + revocationIndex;
            Tail tail = revocationTailsAccessor.access(index);
            omega_num = omega_num.add(tail);
        }

        this.omega = this.omega.add(omega_num.sub(omega_denom));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Witness witness = (Witness) o;

        return omega.equals(witness.omega);
    }
}
