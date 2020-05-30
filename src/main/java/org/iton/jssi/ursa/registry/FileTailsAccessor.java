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

import org.iton.jssi.ursa.pair.CryptoException;
import org.iton.jssi.ursa.pair.PointG2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileTailsAccessor implements RevocationTailsAccessor{

    private static final Logger LOG = LoggerFactory.getLogger(FileTailsAccessor.class);
    private Path path;

    private FileTailsAccessor(Path path){
        this.path = path;
    }

    public static FileTailsAccessor create(Path path, RevocationTailsGenerator generator){

        try {
            if (!Files.exists(path)) {
                Files.createDirectory(path);
                Tail tail = generator.next() ;
                int index = 1;
                while(tail != null){
                    Files.write(Paths.get(path.toString(), String.format("%05d", index++)), tail.toBytes());
                    tail = generator.next();
                }
            } else {
                LOG.debug(String.format("Directory [%s] already exist", path.toString()));
            }
        } catch(IOException e){
            LOG.error(String.format("File operation exception %s", e.getMessage()));
        }

        return new FileTailsAccessor(path);
    }

    @Override
    public Tail access(int index) {
        try {
            byte[] bytes = Files.readAllBytes(Paths.get(path.toString(), String.format("%05d", index)));
            return new Tail(PointG2.fromBytes(bytes));
        } catch(IOException | CryptoException e){
            LOG.error(String.format("File operation exception %s", e.getMessage()));
            return null;
        }
    }
}
