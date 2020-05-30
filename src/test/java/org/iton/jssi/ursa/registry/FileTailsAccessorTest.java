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

import org.iton.jssi.ursa.anoncred.issuer.Issuer;
import org.iton.jssi.ursa.anoncred.issuer.IssuerEmulator;
import org.iton.jssi.ursa.pair.CryptoException;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class FileTailsAccessorTest {

    private static final String TAILS_DIR = "C:\\IntelliJ\\projects";
    Path path = Paths.get(TAILS_DIR, "tails");

    private FileTailsAccessor getFileTailsAccessor() throws CryptoException {

        IssuerEmulator issuer = new IssuerEmulator();

        RevocationRegistryDefinition revocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
                issuer.getCredentialPublicKey(),
                10,
                true);

        return FileTailsAccessor.create(path, revocationRegistryDefinition.revocationTailsGenerator);
    }

    @Test
    void access() throws CryptoException {
        FileTailsAccessor accessor = getFileTailsAccessor();
        Tail tail = accessor.access(1);
        assertNotNull(tail);
    }
}