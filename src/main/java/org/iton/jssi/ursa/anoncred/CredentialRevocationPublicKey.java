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

import org.iton.jssi.ursa.pair.PointG1;
import org.iton.jssi.ursa.pair.PointG2;

public class CredentialRevocationPublicKey {

    public PointG1 g;
    public PointG2 g_dash;
    public PointG1 h;
    public PointG1 h0;
    public PointG1 h1;
    public PointG1 h2;
    public PointG1 h_tilde;
    public PointG2 h_cap;
    public PointG2 u;
    public PointG1 pk;
    public PointG2 y;

    public CredentialRevocationPublicKey(
            PointG1 g,
            PointG2 g_dash,
            PointG1 h,
            PointG1 h0,
            PointG1 h1,
            PointG1 h2,
            PointG1 h_tilde,
            PointG2 h_cap,
            PointG2 u,
            PointG1 pk,
            PointG2 y)
    {
        this.g = g;
        this.g_dash = g_dash;
        this.h = h;
        this.h0 = h0;
        this.h1 = h1;
        this.h2 = h2;
        this.h_tilde = h_tilde;
        this.h_cap = h_cap;
        this.u = u;
        this.pk = pk;
        this.y = y;
    }
}
