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

package org.apache.milagro.amcl.BN254;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FP12Test {

    @Test
    void fromHex() {
        String hex = "1 210B51DBD9726CF0CDBFA3803285C73F17A9E43267F2461FAB2FE4DFE1A46F49 1 08C30A04E07CD7353B10D5D451FD7A6E85892B1BC605543AECC75F938CE0F9C8 1 1D58388870144A5D071871C5E2A1FF0CE7B517380E6ADF7325572D8C7D924D19 1 09E20633DCD5743930A7B4327A4E202957BE0A5793DA336E9DF752222178D515 1 05C57A7A26B08EB6147A80DA5C8083BCCDA2E2F5F57D91DBF2F0D28BFC238578 1 1F9FC5FAF9255E04EE123CC26D4577FAEF96CB92734E9E0722078E07D8BC2728 1 1C9265D1B308C907152A1DEDD6E500C6378DCCDC748141BF232F4C8341CDF86B 1 1761FC0F8284812FA0C83D4081717D6C44637C53E68BE3113E427ACF6366CA59 1 091E6E55B798DA22EBD513826781748A8EF99DA756D9CB7B7AC6CF1D7F34A02E 1 1FC3B54A65D9C07CC87540CE5CC9D391625A75616631E4086028F1B7C5D89541 1 15AC82C66461442C0200D69E0795AC2025746DB33677FE50FF87B423F7E9B883 1 1FC6B6EFFC9FBE71BBD95080A5236180DEBA1BC83BD658EB54FBC188DC2E2167";
        FP12 fp = FP12.fromHex(hex);
        assertEquals(hex, fp.toHex());
    }
}