/*
   Copyright 2019 Evan Saulpaugh

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
package org.iton.jssi.ursa.rlp;

/**
 * Indicates a failure to decode illegal or otherwise undecodeable data as per the RLP spec.
 */
public abstract class DecodeException extends Exception {

    DecodeException(String msg) {
        super(msg);
    }

    DecodeException(Throwable cause) {
        super(cause);
    }

    public abstract boolean isRecoverable();
}
