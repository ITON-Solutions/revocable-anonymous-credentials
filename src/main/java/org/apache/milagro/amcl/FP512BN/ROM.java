/*
	Licensed to the Apache Software Foundation (ASF) under one
	or more contributor license agreements.  See the NOTICE file
	distributed with this work for additional information
	regarding copyright ownership.  The ASF licenses this file
	to you under the Apache License, Version 2.0 (the
	"License"); you may not use this file except in compliance
	with the License.  You may obtain a copy of the License at
	
	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing,
	software distributed under the License is distributed on an
	"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
	KIND, either express or implied.  See the License for the
	specific language governing permissions and limitations
	under the License.
*/

/* Fixed Data in ROM - Field and Curve parameters */


package org.apache.milagro.amcl.FP512BN;

public class ROM
{

// Base Bits= 60
public static final long[] Modulus= {0x4EB280922ADEF33L,0x6A55CE5F4C6467BL,0xC65DEAB236FE191L,0xCF1EACBE98B8E48L,0x3C111B0EF455146L,0xA1D8CB5307C0BBEL,0xFFFF9EC7F01C60BL,0xFFFFFFFFFFFFFFFL,0xFFFFFFFFL};
public static final long[] R2modp= {0x1FA6DCEF99812E9L,0xAB3452895A0B74EL,0xC53EA988C079E1EL,0x1E90E033BA630B9L,0xF1EA41C0714D8B0L,0xE72785387509E28L,0xD86794F834DAB00L,0x9757C2ACCD342A1L,0x44ECB079L};
public static final long MConst= 0x692A189FCCC5C05L;

public static final int CURVE_A= 0;
public static final int CURVE_B_I= 3;
public static final int CURVE_Cof_I= 1;
public static final long[] CURVE_B= {0x3L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L};
public static final long[] CURVE_Order= {0x6A64A5F519A09EDL,0x10313E04F9A2B40L,0xC65DEAB2679A34AL,0xCF1EACBE98B8E48L,0x3C111B0EF445146L,0xA1D8CB5307C0BBEL,0xFFFF9EC7F01C60BL,0xFFFFFFFFFFFFFFFL,0xFFFFFFFFL};
public static final long[] CURVE_Gx= {0x1L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L};
public static final long[] CURVE_Gy= {0x2L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L};

public static final long[] Fra= {0x49617B1F4B73AB2L,0x71514F6202AED1FL,0xF6080D3BD8681E1L,0xF8AA9E852CBBB59L,0xC8CF2E2068398E9L,0x8A5296F791AB26BL,0x196A8C7C68B4EA1L,0xCF5BBF9095A1B79L,0x1EF71AA9L};
public static final long[] Frb= {0x5510572DF6B481L,0xF9047EFD49B595CL,0xD055DD765E95FAFL,0xD6740E396BFD2EEL,0x7341ECEE8C1B85CL,0x1786345B7615952L,0xE695124B876776AL,0x30A4406F6A5E486L,0xE108E556L};
public static final long[] CURVE_Bnx= {0xB306BB5E1BD80FL,0x82F5C030B0F7F01L,0x68L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L};
public static final long[] CURVE_Cof= {0x1L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L};
public static final long[] CURVE_Cru= {0xB0716209C79298AL,0xCEE6799B8B17C14L,0x78966BE526092AEL,0x20089C27507ACD8L,0xF8EF7611FA3074BL,0x6146B86B378EA2CL,0xFFFF9EC7DC83D2AL,0xFFFFFFFFFFFFFFFL,0xFFFFFFFFL};
public static final long[] CURVE_Pxa= {0xF07A96E0DB646B5L,0x18F87319072FFE8L,0x7BE21BCBBC78F22L,0x537863514DC6DC5L,0xDA57CC78CD0B024L,0xD29B358F0DB9B57L,0x7412F3CEA1E4BBBL,0xE138648958801BAL,0x3B165339L};
public static final long[] CURVE_Pxb= {0xDB5CBEFDA8AE0E9L,0xCA411CD88911B3L,0xD6E1383D5ADCE4L,0x227285526E0D5E5L,0xB02566B94D9781EL,0x56DC6C6EF2476A8L,0x680ABE8B4825EA6L,0xF85067E6C89B4C4L,0x481C13CBL};
public static final long[] CURVE_Pya= {0x2480312ADDE67A1L,0xDA17AD615EFB85EL,0x312542808B7BC5CL,0x18BDEC153E8EDD2L,0xE5C158699D4B6CDL,0xB1DF660AFCDD03EL,0xB0CBA374F277085L,0xC827C7B8292EF5AL,0x6F01EC84L};
public static final long[] CURVE_Pyb= {0x58B7186C84F8E8BL,0xF05C2224BF76168L,0x10AD7EE279C08DFL,0x7FC3E2E50714A43L,0x3D04961941DA289L,0x38C118867B0C9B6L,0xC315F75D91F0214L,0x8B04E7831AC3640L,0x51A3BCECL};
public static final long[][] CURVE_W= {{0x110F89749834583L,0x65FB911D16A173FL,0xFFFFFFFFCF63FE9L,0xFFFFFFFFFFFFFFFL,0xFFFFL,0x0L,0x0L,0x0L,0x0L},{0x1660D76BC37B01FL,0x5EB806161EFE02L,0xD1L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L}};
public static final long[][][] CURVE_SB= {{{0xFAAEB208D4B9564L,0x601010BBB4B193CL,0xFFFFFFFFCF63F18L,0xFFFFFFFFFFFFFFFL,0xFFFFL,0x0L,0x0L,0x0L,0x0L},{0x5403CE8956259CEL,0xA45BDA397B2D3EL,0xC65DEAB2679A279L,0xCF1EACBE98B8E48L,0x3C111B0EF445146L,0xA1D8CB5307C0BBEL,0xFFFF9EC7F01C60BL,0xFFFFFFFFFFFFFFFL,0xFFFFFFFFL}},{{0x1660D76BC37B01FL,0x5EB806161EFE02L,0xD1L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x110F89749834583L,0x65FB911D16A173FL,0xFFFFFFFFCF63FE9L,0xFFFFFFFFFFFFFFFL,0xFFFFL,0x0L,0x0L,0x0L,0x0L}}};
public static final long[][] CURVE_WB= {{0x6DAB36AB55A29F0L,0xFC42C60583D30C1L,0x5555555545215FBL,0x555555555555555L,0x5555L,0x0L,0x0L,0x0L,0x0L},{0xEEB012BA2355D4BL,0xF20FC1FD7F84F17L,0x892FA9DE2BB5E5CL,0x74B96064DAD40F5L,0xD76BC3535163152L,0x806161EFE021660L,0xD105EBL,0x0L,0x0L},{0x7CF03F380289AADL,0xBA82C117183E70CL,0xC497D4EF15DAF62L,0x3A5CB0326D6A07AL,0x6BB5E1A9A8B18A9L,0xC030B0F7F010B30L,0x6882F5L,0x0L,0x0L},{0x574A5F3F92279D1L,0xF65745A421E32BFL,0x55555555452152AL,0x555555555555555L,0x5555L,0x0L,0x0L,0x0L,0x0L}};
public static final long[][][] CURVE_BB= {{{0xB306BB5E1BD810L,0x82F5C030B0F7F01L,0x68L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0xB306BB5E1BD80FL,0x82F5C030B0F7F01L,0x68L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0xB306BB5E1BD80FL,0x82F5C030B0F7F01L,0x68L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x5403CE8956259CFL,0xA45BDA397B2D3EL,0xC65DEAB2679A279L,0xCF1EACBE98B8E48L,0x3C111B0EF445146L,0xA1D8CB5307C0BBEL,0xFFFF9EC7F01C60BL,0xFFFFFFFFFFFFFFFL,0xFFFFFFFFL}},{{0x1660D76BC37B01FL,0x5EB806161EFE02L,0xD1L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x5F343A3F37E31DEL,0x8D3B7DD448AAC3FL,0xC65DEAB2679A2E1L,0xCF1EACBE98B8E48L,0x3C111B0EF445146L,0xA1D8CB5307C0BBEL,0xFFFF9EC7F01C60BL,0xFFFFFFFFFFFFFFFL,0xFFFFFFFFL},{0x5F343A3F37E31DDL,0x8D3B7DD448AAC3FL,0xC65DEAB2679A2E1L,0xCF1EACBE98B8E48L,0x3C111B0EF445146L,0xA1D8CB5307C0BBEL,0xFFFF9EC7F01C60BL,0xFFFFFFFFFFFFFFFL,0xFFFFFFFFL},{0x5F343A3F37E31DEL,0x8D3B7DD448AAC3FL,0xC65DEAB2679A2E1L,0xCF1EACBE98B8E48L,0x3C111B0EF445146L,0xA1D8CB5307C0BBEL,0xFFFF9EC7F01C60BL,0xFFFFFFFFFFFFFFFL,0xFFFFFFFFL}},{{0x1660D76BC37B01EL,0x5EB806161EFE02L,0xD1L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x1660D76BC37B01FL,0x5EB806161EFE02L,0xD1L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x1660D76BC37B01FL,0x5EB806161EFE02L,0xD1L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x1660D76BC37B01FL,0x5EB806161EFE02L,0xD1L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L}},{{0x5F343A3F37E31DFL,0x8D3B7DD448AAC3FL,0xC65DEAB2679A2E1L,0xCF1EACBE98B8E48L,0x3C111B0EF445146L,0xA1D8CB5307C0BBEL,0xFFFF9EC7F01C60BL,0xFFFFFFFFFFFFFFFL,0xFFFFFFFFL},{0x3DA2F71D92AA9AFL,0x45A3D4235C2F3CL,0xC65DEAB2679A1A8L,0xCF1EACBE98B8E48L,0x3C111B0EF445146L,0xA1D8CB5307C0BBEL,0xFFFF9EC7F01C60BL,0xFFFFFFFFFFFFFFFL,0xFFFFFFFFL},{0x1660D76BC37B01DL,0x5EB806161EFE02L,0xD1L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x5F343A3F37E31DFL,0x8D3B7DD448AAC3FL,0xC65DEAB2679A2E1L,0xCF1EACBE98B8E48L,0x3C111B0EF445146L,0xA1D8CB5307C0BBEL,0xFFFF9EC7F01C60BL,0xFFFFFFFFFFFFFFFL,0xFFFFFFFFL}}};

}

