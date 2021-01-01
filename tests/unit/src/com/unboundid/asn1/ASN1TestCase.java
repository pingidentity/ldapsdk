/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2007-2021 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.asn1;



import java.util.ArrayList;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides the superclass for all ASN.1 test cases.
 */
@Test(sequential=true)
public abstract class ASN1TestCase
       extends LDAPSDKTestCase

{
  /**
   * Retrieves a set of BER types that can be used for testing construction.
   * This includes the entire set of possible single-byte types, which is all
   * that we will attempt to handle.
   *
   * @return  A set of BER types that can be used for testing.
   */
  @DataProvider(name = "testTypes")
  public Object[][] getTestTypes()
  {
    return new Object[][]
    {
      // Universal primitive
      new Object[] { (byte) 0x00 },
      new Object[] { (byte) 0x01 },
      new Object[] { (byte) 0x02 },
      new Object[] { (byte) 0x03 },
      new Object[] { (byte) 0x04 },
      new Object[] { (byte) 0x05 },
      new Object[] { (byte) 0x06 },
      new Object[] { (byte) 0x07 },
      new Object[] { (byte) 0x08 },
      new Object[] { (byte) 0x09 },
      new Object[] { (byte) 0x0A },
      new Object[] { (byte) 0x0B },
      new Object[] { (byte) 0x0C },
      new Object[] { (byte) 0x0D },
      new Object[] { (byte) 0x0E },
      new Object[] { (byte) 0x0F },
      new Object[] { (byte) 0x10 },
      new Object[] { (byte) 0x11 },
      new Object[] { (byte) 0x12 },
      new Object[] { (byte) 0x13 },
      new Object[] { (byte) 0x14 },
      new Object[] { (byte) 0x15 },
      new Object[] { (byte) 0x16 },
      new Object[] { (byte) 0x17 },
      new Object[] { (byte) 0x18 },
      new Object[] { (byte) 0x19 },
      new Object[] { (byte) 0x1A },
      new Object[] { (byte) 0x1B },
      new Object[] { (byte) 0x1C },
      new Object[] { (byte) 0x1D },
      new Object[] { (byte) 0x1E },

      // Universal constructed
      new Object[] { (byte) 0x20 },
      new Object[] { (byte) 0x21 },
      new Object[] { (byte) 0x22 },
      new Object[] { (byte) 0x23 },
      new Object[] { (byte) 0x24 },
      new Object[] { (byte) 0x25 },
      new Object[] { (byte) 0x26 },
      new Object[] { (byte) 0x27 },
      new Object[] { (byte) 0x28 },
      new Object[] { (byte) 0x29 },
      new Object[] { (byte) 0x2A },
      new Object[] { (byte) 0x2B },
      new Object[] { (byte) 0x2C },
      new Object[] { (byte) 0x2D },
      new Object[] { (byte) 0x2E },
      new Object[] { (byte) 0x2F },
      new Object[] { (byte) 0x30 },
      new Object[] { (byte) 0x31 },
      new Object[] { (byte) 0x32 },
      new Object[] { (byte) 0x33 },
      new Object[] { (byte) 0x34 },
      new Object[] { (byte) 0x35 },
      new Object[] { (byte) 0x36 },
      new Object[] { (byte) 0x37 },
      new Object[] { (byte) 0x38 },
      new Object[] { (byte) 0x39 },
      new Object[] { (byte) 0x3A },
      new Object[] { (byte) 0x3B },
      new Object[] { (byte) 0x3C },
      new Object[] { (byte) 0x3D },
      new Object[] { (byte) 0x3E },

      // Application-specific primitive
      new Object[] { (byte) 0x40 },
      new Object[] { (byte) 0x41 },
      new Object[] { (byte) 0x42 },
      new Object[] { (byte) 0x43 },
      new Object[] { (byte) 0x44 },
      new Object[] { (byte) 0x45 },
      new Object[] { (byte) 0x46 },
      new Object[] { (byte) 0x47 },
      new Object[] { (byte) 0x48 },
      new Object[] { (byte) 0x49 },
      new Object[] { (byte) 0x4A },
      new Object[] { (byte) 0x4B },
      new Object[] { (byte) 0x4C },
      new Object[] { (byte) 0x4D },
      new Object[] { (byte) 0x4E },
      new Object[] { (byte) 0x4F },
      new Object[] { (byte) 0x50 },
      new Object[] { (byte) 0x51 },
      new Object[] { (byte) 0x52 },
      new Object[] { (byte) 0x53 },
      new Object[] { (byte) 0x54 },
      new Object[] { (byte) 0x55 },
      new Object[] { (byte) 0x56 },
      new Object[] { (byte) 0x57 },
      new Object[] { (byte) 0x58 },
      new Object[] { (byte) 0x59 },
      new Object[] { (byte) 0x5A },
      new Object[] { (byte) 0x5B },
      new Object[] { (byte) 0x5C },
      new Object[] { (byte) 0x5D },
      new Object[] { (byte) 0x5E },

      // Application-specific constructed
      new Object[] { (byte) 0x60 },
      new Object[] { (byte) 0x61 },
      new Object[] { (byte) 0x62 },
      new Object[] { (byte) 0x63 },
      new Object[] { (byte) 0x64 },
      new Object[] { (byte) 0x65 },
      new Object[] { (byte) 0x66 },
      new Object[] { (byte) 0x67 },
      new Object[] { (byte) 0x68 },
      new Object[] { (byte) 0x69 },
      new Object[] { (byte) 0x6A },
      new Object[] { (byte) 0x6B },
      new Object[] { (byte) 0x6C },
      new Object[] { (byte) 0x6D },
      new Object[] { (byte) 0x6E },
      new Object[] { (byte) 0x6F },
      new Object[] { (byte) 0x70 },
      new Object[] { (byte) 0x71 },
      new Object[] { (byte) 0x72 },
      new Object[] { (byte) 0x73 },
      new Object[] { (byte) 0x74 },
      new Object[] { (byte) 0x75 },
      new Object[] { (byte) 0x76 },
      new Object[] { (byte) 0x77 },
      new Object[] { (byte) 0x78 },
      new Object[] { (byte) 0x79 },
      new Object[] { (byte) 0x7A },
      new Object[] { (byte) 0x7B },
      new Object[] { (byte) 0x7C },
      new Object[] { (byte) 0x7D },
      new Object[] { (byte) 0x7E },

      // Context-specific primitive
      new Object[] { (byte) 0x80 },
      new Object[] { (byte) 0x81 },
      new Object[] { (byte) 0x82 },
      new Object[] { (byte) 0x83 },
      new Object[] { (byte) 0x84 },
      new Object[] { (byte) 0x85 },
      new Object[] { (byte) 0x86 },
      new Object[] { (byte) 0x87 },
      new Object[] { (byte) 0x88 },
      new Object[] { (byte) 0x89 },
      new Object[] { (byte) 0x8A },
      new Object[] { (byte) 0x8B },
      new Object[] { (byte) 0x8C },
      new Object[] { (byte) 0x8D },
      new Object[] { (byte) 0x8E },
      new Object[] { (byte) 0x8F },
      new Object[] { (byte) 0x90 },
      new Object[] { (byte) 0x91 },
      new Object[] { (byte) 0x92 },
      new Object[] { (byte) 0x93 },
      new Object[] { (byte) 0x94 },
      new Object[] { (byte) 0x95 },
      new Object[] { (byte) 0x96 },
      new Object[] { (byte) 0x97 },
      new Object[] { (byte) 0x98 },
      new Object[] { (byte) 0x99 },
      new Object[] { (byte) 0x9A },
      new Object[] { (byte) 0x9B },
      new Object[] { (byte) 0x9C },
      new Object[] { (byte) 0x9D },
      new Object[] { (byte) 0x9E },

      // Context-specific constructed
      new Object[] { (byte) 0xA0 },
      new Object[] { (byte) 0xA1 },
      new Object[] { (byte) 0xA2 },
      new Object[] { (byte) 0xA3 },
      new Object[] { (byte) 0xA4 },
      new Object[] { (byte) 0xA5 },
      new Object[] { (byte) 0xA6 },
      new Object[] { (byte) 0xA7 },
      new Object[] { (byte) 0xA8 },
      new Object[] { (byte) 0xA9 },
      new Object[] { (byte) 0xAA },
      new Object[] { (byte) 0xAB },
      new Object[] { (byte) 0xAC },
      new Object[] { (byte) 0xAD },
      new Object[] { (byte) 0xAE },
      new Object[] { (byte) 0xAF },
      new Object[] { (byte) 0xB0 },
      new Object[] { (byte) 0xB1 },
      new Object[] { (byte) 0xB2 },
      new Object[] { (byte) 0xB3 },
      new Object[] { (byte) 0xB4 },
      new Object[] { (byte) 0xB5 },
      new Object[] { (byte) 0xB6 },
      new Object[] { (byte) 0xB7 },
      new Object[] { (byte) 0xB8 },
      new Object[] { (byte) 0xB9 },
      new Object[] { (byte) 0xBA },
      new Object[] { (byte) 0xBB },
      new Object[] { (byte) 0xBC },
      new Object[] { (byte) 0xBD },
      new Object[] { (byte) 0xBE },

      // Private primitive
      new Object[] { (byte) 0xC0 },
      new Object[] { (byte) 0xC1 },
      new Object[] { (byte) 0xC2 },
      new Object[] { (byte) 0xC3 },
      new Object[] { (byte) 0xC4 },
      new Object[] { (byte) 0xC5 },
      new Object[] { (byte) 0xC6 },
      new Object[] { (byte) 0xC7 },
      new Object[] { (byte) 0xC8 },
      new Object[] { (byte) 0xC9 },
      new Object[] { (byte) 0xCA },
      new Object[] { (byte) 0xCB },
      new Object[] { (byte) 0xCC },
      new Object[] { (byte) 0xCD },
      new Object[] { (byte) 0xCE },
      new Object[] { (byte) 0xCF },
      new Object[] { (byte) 0xD0 },
      new Object[] { (byte) 0xD1 },
      new Object[] { (byte) 0xD2 },
      new Object[] { (byte) 0xD3 },
      new Object[] { (byte) 0xD4 },
      new Object[] { (byte) 0xD5 },
      new Object[] { (byte) 0xD6 },
      new Object[] { (byte) 0xD7 },
      new Object[] { (byte) 0xD8 },
      new Object[] { (byte) 0xD9 },
      new Object[] { (byte) 0xDA },
      new Object[] { (byte) 0xDB },
      new Object[] { (byte) 0xDC },
      new Object[] { (byte) 0xDD },
      new Object[] { (byte) 0xDE },

      // Private constructed
      new Object[] { (byte) 0xE0 },
      new Object[] { (byte) 0xE1 },
      new Object[] { (byte) 0xE2 },
      new Object[] { (byte) 0xE3 },
      new Object[] { (byte) 0xE4 },
      new Object[] { (byte) 0xE5 },
      new Object[] { (byte) 0xE6 },
      new Object[] { (byte) 0xE7 },
      new Object[] { (byte) 0xE8 },
      new Object[] { (byte) 0xE9 },
      new Object[] { (byte) 0xEA },
      new Object[] { (byte) 0xEB },
      new Object[] { (byte) 0xEC },
      new Object[] { (byte) 0xED },
      new Object[] { (byte) 0xEE },
      new Object[] { (byte) 0xEF },
      new Object[] { (byte) 0xF0 },
      new Object[] { (byte) 0xF1 },
      new Object[] { (byte) 0xF2 },
      new Object[] { (byte) 0xF3 },
      new Object[] { (byte) 0xF4 },
      new Object[] { (byte) 0xF5 },
      new Object[] { (byte) 0xF6 },
      new Object[] { (byte) 0xF7 },
      new Object[] { (byte) 0xF8 },
      new Object[] { (byte) 0xF9 },
      new Object[] { (byte) 0xFA },
      new Object[] { (byte) 0xFB },
      new Object[] { (byte) 0xFC },
      new Object[] { (byte) 0xFD },
      new Object[] { (byte) 0xFE }
     };
  }



  /**
   * Retrieves a set of types and values that can be used for testing purposes.
   *
   * @return  A set of types and values that can be used for testing purposes.
   */
  @DataProvider(name = "testTypesAndValues")
  public Object[][] getTestTypesAndValues()
  {
    return new Object[][]
    {
      new Object[] { (byte) 0x00, (byte[]) null },
      new Object[] { (byte) 0x00, new byte[0] },
      new Object[] { (byte) 0x00, new byte[1] },
      new Object[] { (byte) 0x00, new byte[2] },
      new Object[] { (byte) 0x00, new byte[3] },
      new Object[] { (byte) 0x00, new byte[4] },
      new Object[] { (byte) 0x00, new byte[5] },
      new Object[] { (byte) 0x00, new byte[6] },
      new Object[] { (byte) 0x00, new byte[7] },
      new Object[] { (byte) 0x00, new byte[8] },
      new Object[] { (byte) 0x00, new byte[9] },
      new Object[] { (byte) 0x00, new byte[10] },
      new Object[] { (byte) 0x00, new byte[11] },
      new Object[] { (byte) 0x00, new byte[12] },
      new Object[] { (byte) 0x00, new byte[13] },
      new Object[] { (byte) 0x00, new byte[14] },
      new Object[] { (byte) 0x00, new byte[15] },
      new Object[] { (byte) 0x00, new byte[16] },
      new Object[] { (byte) 0x00, new byte[17] },
      new Object[] { (byte) 0x00, new byte[18] },
      new Object[] { (byte) 0x00, new byte[19] },
      new Object[] { (byte) 0x00, new byte[20] },
      new Object[] { (byte) 0x00, new byte[21] },
      new Object[] { (byte) 0x00, new byte[22] },
      new Object[] { (byte) 0x00, new byte[23] },
      new Object[] { (byte) 0x00, new byte[24] },
      new Object[] { (byte) 0x00, new byte[25] },
      new Object[] { (byte) 0x00, new byte[26] },
      new Object[] { (byte) 0x00, new byte[27] },
      new Object[] { (byte) 0x00, new byte[28] },
      new Object[] { (byte) 0x00, new byte[29] },
      new Object[] { (byte) 0x00, new byte[30] },
      new Object[] { (byte) 0x00, new byte[31] },
      new Object[] { (byte) 0x00, new byte[32] },
      new Object[] { (byte) 0x00, new byte[33] },
      new Object[] { (byte) 0x00, new byte[34] },
      new Object[] { (byte) 0x00, new byte[35] },
      new Object[] { (byte) 0x00, new byte[36] },
      new Object[] { (byte) 0x00, new byte[37] },
      new Object[] { (byte) 0x00, new byte[38] },
      new Object[] { (byte) 0x00, new byte[39] },
      new Object[] { (byte) 0x00, new byte[40] },
      new Object[] { (byte) 0x00, new byte[41] },
      new Object[] { (byte) 0x00, new byte[42] },
      new Object[] { (byte) 0x00, new byte[43] },
      new Object[] { (byte) 0x00, new byte[44] },
      new Object[] { (byte) 0x00, new byte[45] },
      new Object[] { (byte) 0x00, new byte[46] },
      new Object[] { (byte) 0x00, new byte[47] },
      new Object[] { (byte) 0x00, new byte[48] },
      new Object[] { (byte) 0x00, new byte[49] },
      new Object[] { (byte) 0x00, new byte[50] },
      new Object[] { (byte) 0x00, new byte[51] },
      new Object[] { (byte) 0x00, new byte[52] },
      new Object[] { (byte) 0x00, new byte[53] },
      new Object[] { (byte) 0x00, new byte[54] },
      new Object[] { (byte) 0x00, new byte[55] },
      new Object[] { (byte) 0x00, new byte[56] },
      new Object[] { (byte) 0x00, new byte[57] },
      new Object[] { (byte) 0x00, new byte[58] },
      new Object[] { (byte) 0x00, new byte[59] },
      new Object[] { (byte) 0x00, new byte[60] },
      new Object[] { (byte) 0x00, new byte[61] },
      new Object[] { (byte) 0x00, new byte[62] },
      new Object[] { (byte) 0x00, new byte[63] },
      new Object[] { (byte) 0x00, new byte[64] },
      new Object[] { (byte) 0x00, new byte[65] },
      new Object[] { (byte) 0x00, new byte[66] },
      new Object[] { (byte) 0x00, new byte[67] },
      new Object[] { (byte) 0x00, new byte[68] },
      new Object[] { (byte) 0x00, new byte[69] },
      new Object[] { (byte) 0x00, new byte[70] },
      new Object[] { (byte) 0x00, new byte[71] },
      new Object[] { (byte) 0x00, new byte[72] },
      new Object[] { (byte) 0x00, new byte[73] },
      new Object[] { (byte) 0x00, new byte[74] },
      new Object[] { (byte) 0x00, new byte[75] },
      new Object[] { (byte) 0x00, new byte[76] },
      new Object[] { (byte) 0x00, new byte[77] },
      new Object[] { (byte) 0x00, new byte[78] },
      new Object[] { (byte) 0x00, new byte[79] },
      new Object[] { (byte) 0x00, new byte[80] },
      new Object[] { (byte) 0x00, new byte[81] },
      new Object[] { (byte) 0x00, new byte[82] },
      new Object[] { (byte) 0x00, new byte[83] },
      new Object[] { (byte) 0x00, new byte[84] },
      new Object[] { (byte) 0x00, new byte[85] },
      new Object[] { (byte) 0x00, new byte[86] },
      new Object[] { (byte) 0x00, new byte[87] },
      new Object[] { (byte) 0x00, new byte[88] },
      new Object[] { (byte) 0x00, new byte[89] },
      new Object[] { (byte) 0x00, new byte[90] },
      new Object[] { (byte) 0x00, new byte[91] },
      new Object[] { (byte) 0x00, new byte[92] },
      new Object[] { (byte) 0x00, new byte[93] },
      new Object[] { (byte) 0x00, new byte[94] },
      new Object[] { (byte) 0x00, new byte[95] },
      new Object[] { (byte) 0x00, new byte[96] },
      new Object[] { (byte) 0x00, new byte[97] },
      new Object[] { (byte) 0x00, new byte[98] },
      new Object[] { (byte) 0x00, new byte[99] },
      new Object[] { (byte) 0x00, new byte[100] },
      new Object[] { (byte) 0x00, new byte[101] },
      new Object[] { (byte) 0x00, new byte[102] },
      new Object[] { (byte) 0x00, new byte[103] },
      new Object[] { (byte) 0x00, new byte[104] },
      new Object[] { (byte) 0x00, new byte[105] },
      new Object[] { (byte) 0x00, new byte[106] },
      new Object[] { (byte) 0x00, new byte[107] },
      new Object[] { (byte) 0x00, new byte[108] },
      new Object[] { (byte) 0x00, new byte[109] },
      new Object[] { (byte) 0x00, new byte[110] },
      new Object[] { (byte) 0x00, new byte[111] },
      new Object[] { (byte) 0x00, new byte[112] },
      new Object[] { (byte) 0x00, new byte[113] },
      new Object[] { (byte) 0x00, new byte[114] },
      new Object[] { (byte) 0x00, new byte[115] },
      new Object[] { (byte) 0x00, new byte[116] },
      new Object[] { (byte) 0x00, new byte[117] },
      new Object[] { (byte) 0x00, new byte[118] },
      new Object[] { (byte) 0x00, new byte[119] },
      new Object[] { (byte) 0x00, new byte[120] },
      new Object[] { (byte) 0x00, new byte[121] },
      new Object[] { (byte) 0x00, new byte[122] },
      new Object[] { (byte) 0x00, new byte[123] },
      new Object[] { (byte) 0x00, new byte[124] },
      new Object[] { (byte) 0x00, new byte[125] },
      new Object[] { (byte) 0x00, new byte[126] },
      new Object[] { (byte) 0x00, new byte[127] },
      new Object[] { (byte) 0x00, new byte[128] },
      new Object[] { (byte) 0x00, new byte[129] },
      new Object[] { (byte) 0x00, new byte[254] },
      new Object[] { (byte) 0x00, new byte[255] },
      new Object[] { (byte) 0x00, new byte[256] },
      new Object[] { (byte) 0x00, new byte[257] },
      new Object[] { (byte) 0x00, new byte[4094] },
      new Object[] { (byte) 0x00, new byte[4095] },
      new Object[] { (byte) 0x00, new byte[4096] },
      new Object[] { (byte) 0x00, new byte[4097] },
      new Object[] { (byte) 0x00, new byte[65534] },
      new Object[] { (byte) 0x00, new byte[65535] },
      new Object[] { (byte) 0x00, new byte[65536] },
      new Object[] { (byte) 0x00, new byte[65537] },
     };
  }



  /**
   * Retrieves a set of test integer values.
   *
   * @return  A set of test integer values.
   */
  @DataProvider(name = "testIntegers")
  public Object[][] getTestIntegers()
  {
    return new Object[][]
    {
      new Object[] { Integer.valueOf(0) },
      new Object[] { Integer.valueOf(1) },
      new Object[] { Integer.valueOf(2) },
      new Object[] { Integer.valueOf(3) },
      new Object[] { Integer.valueOf(4) },
      new Object[] { Integer.valueOf(5) },
      new Object[] { Integer.valueOf(6) },
      new Object[] { Integer.valueOf(7) },
      new Object[] { Integer.valueOf(8) },
      new Object[] { Integer.valueOf(9) },
      new Object[] { Integer.valueOf(10) },
      new Object[] { Integer.valueOf(11) },
      new Object[] { Integer.valueOf(12) },
      new Object[] { Integer.valueOf(13) },
      new Object[] { Integer.valueOf(14) },
      new Object[] { Integer.valueOf(15) },
      new Object[] { Integer.valueOf(16) },
      new Object[] { Integer.valueOf(17) },
      new Object[] { Integer.valueOf(18) },
      new Object[] { Integer.valueOf(19) },
      new Object[] { Integer.valueOf(20) },
      new Object[] { Integer.valueOf(21) },
      new Object[] { Integer.valueOf(22) },
      new Object[] { Integer.valueOf(23) },
      new Object[] { Integer.valueOf(24) },
      new Object[] { Integer.valueOf(25) },
      new Object[] { Integer.valueOf(26) },
      new Object[] { Integer.valueOf(27) },
      new Object[] { Integer.valueOf(28) },
      new Object[] { Integer.valueOf(29) },
      new Object[] { Integer.valueOf(30) },
      new Object[] { Integer.valueOf(31) },
      new Object[] { Integer.valueOf(32) },
      new Object[] { Integer.valueOf(33) },
      new Object[] { Integer.valueOf(34) },
      new Object[] { Integer.valueOf(35) },
      new Object[] { Integer.valueOf(36) },
      new Object[] { Integer.valueOf(37) },
      new Object[] { Integer.valueOf(38) },
      new Object[] { Integer.valueOf(39) },
      new Object[] { Integer.valueOf(40) },
      new Object[] { Integer.valueOf(41) },
      new Object[] { Integer.valueOf(42) },
      new Object[] { Integer.valueOf(43) },
      new Object[] { Integer.valueOf(44) },
      new Object[] { Integer.valueOf(45) },
      new Object[] { Integer.valueOf(46) },
      new Object[] { Integer.valueOf(47) },
      new Object[] { Integer.valueOf(48) },
      new Object[] { Integer.valueOf(49) },
      new Object[] { Integer.valueOf(50) },
      new Object[] { Integer.valueOf(51) },
      new Object[] { Integer.valueOf(52) },
      new Object[] { Integer.valueOf(53) },
      new Object[] { Integer.valueOf(54) },
      new Object[] { Integer.valueOf(55) },
      new Object[] { Integer.valueOf(56) },
      new Object[] { Integer.valueOf(57) },
      new Object[] { Integer.valueOf(58) },
      new Object[] { Integer.valueOf(59) },
      new Object[] { Integer.valueOf(60) },
      new Object[] { Integer.valueOf(61) },
      new Object[] { Integer.valueOf(62) },
      new Object[] { Integer.valueOf(63) },
      new Object[] { Integer.valueOf(64) },
      new Object[] { Integer.valueOf(65) },
      new Object[] { Integer.valueOf(66) },
      new Object[] { Integer.valueOf(67) },
      new Object[] { Integer.valueOf(68) },
      new Object[] { Integer.valueOf(69) },
      new Object[] { Integer.valueOf(70) },
      new Object[] { Integer.valueOf(71) },
      new Object[] { Integer.valueOf(72) },
      new Object[] { Integer.valueOf(73) },
      new Object[] { Integer.valueOf(74) },
      new Object[] { Integer.valueOf(75) },
      new Object[] { Integer.valueOf(76) },
      new Object[] { Integer.valueOf(77) },
      new Object[] { Integer.valueOf(78) },
      new Object[] { Integer.valueOf(79) },
      new Object[] { Integer.valueOf(80) },
      new Object[] { Integer.valueOf(81) },
      new Object[] { Integer.valueOf(82) },
      new Object[] { Integer.valueOf(83) },
      new Object[] { Integer.valueOf(84) },
      new Object[] { Integer.valueOf(85) },
      new Object[] { Integer.valueOf(86) },
      new Object[] { Integer.valueOf(87) },
      new Object[] { Integer.valueOf(88) },
      new Object[] { Integer.valueOf(89) },
      new Object[] { Integer.valueOf(90) },
      new Object[] { Integer.valueOf(91) },
      new Object[] { Integer.valueOf(92) },
      new Object[] { Integer.valueOf(93) },
      new Object[] { Integer.valueOf(94) },
      new Object[] { Integer.valueOf(95) },
      new Object[] { Integer.valueOf(96) },
      new Object[] { Integer.valueOf(97) },
      new Object[] { Integer.valueOf(98) },
      new Object[] { Integer.valueOf(99) },
      new Object[] { Integer.valueOf(100) },
      new Object[] { Integer.valueOf(101) },
      new Object[] { Integer.valueOf(102) },
      new Object[] { Integer.valueOf(103) },
      new Object[] { Integer.valueOf(104) },
      new Object[] { Integer.valueOf(105) },
      new Object[] { Integer.valueOf(106) },
      new Object[] { Integer.valueOf(107) },
      new Object[] { Integer.valueOf(108) },
      new Object[] { Integer.valueOf(109) },
      new Object[] { Integer.valueOf(110) },
      new Object[] { Integer.valueOf(111) },
      new Object[] { Integer.valueOf(112) },
      new Object[] { Integer.valueOf(113) },
      new Object[] { Integer.valueOf(114) },
      new Object[] { Integer.valueOf(115) },
      new Object[] { Integer.valueOf(116) },
      new Object[] { Integer.valueOf(117) },
      new Object[] { Integer.valueOf(118) },
      new Object[] { Integer.valueOf(119) },
      new Object[] { Integer.valueOf(120) },
      new Object[] { Integer.valueOf(121) },
      new Object[] { Integer.valueOf(122) },
      new Object[] { Integer.valueOf(123) },
      new Object[] { Integer.valueOf(124) },
      new Object[] { Integer.valueOf(125) },
      new Object[] { Integer.valueOf(126) },
      new Object[] { Integer.valueOf(127) },
      new Object[] { Integer.valueOf(128) },
      new Object[] { Integer.valueOf(129) },
      new Object[] { Integer.valueOf(254) },
      new Object[] { Integer.valueOf(255) },
      new Object[] { Integer.valueOf(256) },
      new Object[] { Integer.valueOf(257) },
      new Object[] { Integer.valueOf(4094) },
      new Object[] { Integer.valueOf(4095) },
      new Object[] { Integer.valueOf(4096) },
      new Object[] { Integer.valueOf(4097) },
      new Object[] { Integer.valueOf(65534) },
      new Object[] { Integer.valueOf(65535) },
      new Object[] { Integer.valueOf(65536) },
      new Object[] { Integer.valueOf(65537) },
      new Object[] { Integer.valueOf(1048574) },
      new Object[] { Integer.valueOf(1048575) },
      new Object[] { Integer.valueOf(1048576) },
      new Object[] { Integer.valueOf(1048577) },
      new Object[] { Integer.valueOf(16777214) },
      new Object[] { Integer.valueOf(16777215) },
      new Object[] { Integer.valueOf(16777216) },
      new Object[] { Integer.valueOf(16777217) },
      new Object[] { Integer.valueOf(268435454) },
      new Object[] { Integer.valueOf(268435455) },
      new Object[] { Integer.valueOf(268435456) },
      new Object[] { Integer.valueOf(268435457) },
      new Object[] { Integer.valueOf(Integer.MAX_VALUE) },
      new Object[] { Integer.valueOf(-1) },
      new Object[] { Integer.valueOf(-2) },
      new Object[] { Integer.valueOf(-3) },
      new Object[] { Integer.valueOf(-4) },
      new Object[] { Integer.valueOf(-5) },
      new Object[] { Integer.valueOf(-6) },
      new Object[] { Integer.valueOf(-7) },
      new Object[] { Integer.valueOf(-8) },
      new Object[] { Integer.valueOf(-9) },
      new Object[] { Integer.valueOf(-10) },
      new Object[] { Integer.valueOf(-11) },
      new Object[] { Integer.valueOf(-12) },
      new Object[] { Integer.valueOf(-13) },
      new Object[] { Integer.valueOf(-14) },
      new Object[] { Integer.valueOf(-15) },
      new Object[] { Integer.valueOf(-16) },
      new Object[] { Integer.valueOf(-17) },
      new Object[] { Integer.valueOf(-18) },
      new Object[] { Integer.valueOf(-19) },
      new Object[] { Integer.valueOf(-20) },
      new Object[] { Integer.valueOf(-21) },
      new Object[] { Integer.valueOf(-22) },
      new Object[] { Integer.valueOf(-23) },
      new Object[] { Integer.valueOf(-24) },
      new Object[] { Integer.valueOf(-25) },
      new Object[] { Integer.valueOf(-26) },
      new Object[] { Integer.valueOf(-27) },
      new Object[] { Integer.valueOf(-28) },
      new Object[] { Integer.valueOf(-29) },
      new Object[] { Integer.valueOf(-30) },
      new Object[] { Integer.valueOf(-31) },
      new Object[] { Integer.valueOf(-32) },
      new Object[] { Integer.valueOf(-33) },
      new Object[] { Integer.valueOf(-34) },
      new Object[] { Integer.valueOf(-35) },
      new Object[] { Integer.valueOf(-36) },
      new Object[] { Integer.valueOf(-37) },
      new Object[] { Integer.valueOf(-38) },
      new Object[] { Integer.valueOf(-39) },
      new Object[] { Integer.valueOf(-40) },
      new Object[] { Integer.valueOf(-41) },
      new Object[] { Integer.valueOf(-42) },
      new Object[] { Integer.valueOf(-43) },
      new Object[] { Integer.valueOf(-44) },
      new Object[] { Integer.valueOf(-45) },
      new Object[] { Integer.valueOf(-46) },
      new Object[] { Integer.valueOf(-47) },
      new Object[] { Integer.valueOf(-48) },
      new Object[] { Integer.valueOf(-49) },
      new Object[] { Integer.valueOf(-50) },
      new Object[] { Integer.valueOf(-51) },
      new Object[] { Integer.valueOf(-52) },
      new Object[] { Integer.valueOf(-53) },
      new Object[] { Integer.valueOf(-54) },
      new Object[] { Integer.valueOf(-55) },
      new Object[] { Integer.valueOf(-56) },
      new Object[] { Integer.valueOf(-57) },
      new Object[] { Integer.valueOf(-58) },
      new Object[] { Integer.valueOf(-59) },
      new Object[] { Integer.valueOf(-60) },
      new Object[] { Integer.valueOf(-61) },
      new Object[] { Integer.valueOf(-62) },
      new Object[] { Integer.valueOf(-63) },
      new Object[] { Integer.valueOf(-64) },
      new Object[] { Integer.valueOf(-65) },
      new Object[] { Integer.valueOf(-66) },
      new Object[] { Integer.valueOf(-67) },
      new Object[] { Integer.valueOf(-68) },
      new Object[] { Integer.valueOf(-69) },
      new Object[] { Integer.valueOf(-70) },
      new Object[] { Integer.valueOf(-71) },
      new Object[] { Integer.valueOf(-72) },
      new Object[] { Integer.valueOf(-73) },
      new Object[] { Integer.valueOf(-74) },
      new Object[] { Integer.valueOf(-75) },
      new Object[] { Integer.valueOf(-76) },
      new Object[] { Integer.valueOf(-77) },
      new Object[] { Integer.valueOf(-78) },
      new Object[] { Integer.valueOf(-79) },
      new Object[] { Integer.valueOf(-80) },
      new Object[] { Integer.valueOf(-81) },
      new Object[] { Integer.valueOf(-82) },
      new Object[] { Integer.valueOf(-83) },
      new Object[] { Integer.valueOf(-84) },
      new Object[] { Integer.valueOf(-85) },
      new Object[] { Integer.valueOf(-86) },
      new Object[] { Integer.valueOf(-87) },
      new Object[] { Integer.valueOf(-88) },
      new Object[] { Integer.valueOf(-89) },
      new Object[] { Integer.valueOf(-90) },
      new Object[] { Integer.valueOf(-91) },
      new Object[] { Integer.valueOf(-92) },
      new Object[] { Integer.valueOf(-93) },
      new Object[] { Integer.valueOf(-94) },
      new Object[] { Integer.valueOf(-95) },
      new Object[] { Integer.valueOf(-96) },
      new Object[] { Integer.valueOf(-97) },
      new Object[] { Integer.valueOf(-98) },
      new Object[] { Integer.valueOf(-99) },
      new Object[] { Integer.valueOf(-100) },
      new Object[] { Integer.valueOf(-101) },
      new Object[] { Integer.valueOf(-102) },
      new Object[] { Integer.valueOf(-103) },
      new Object[] { Integer.valueOf(-104) },
      new Object[] { Integer.valueOf(-105) },
      new Object[] { Integer.valueOf(-106) },
      new Object[] { Integer.valueOf(-107) },
      new Object[] { Integer.valueOf(-108) },
      new Object[] { Integer.valueOf(-109) },
      new Object[] { Integer.valueOf(-110) },
      new Object[] { Integer.valueOf(-111) },
      new Object[] { Integer.valueOf(-112) },
      new Object[] { Integer.valueOf(-113) },
      new Object[] { Integer.valueOf(-114) },
      new Object[] { Integer.valueOf(-115) },
      new Object[] { Integer.valueOf(-116) },
      new Object[] { Integer.valueOf(-117) },
      new Object[] { Integer.valueOf(-118) },
      new Object[] { Integer.valueOf(-119) },
      new Object[] { Integer.valueOf(-120) },
      new Object[] { Integer.valueOf(-121) },
      new Object[] { Integer.valueOf(-122) },
      new Object[] { Integer.valueOf(-123) },
      new Object[] { Integer.valueOf(-124) },
      new Object[] { Integer.valueOf(-125) },
      new Object[] { Integer.valueOf(-126) },
      new Object[] { Integer.valueOf(-127) },
      new Object[] { Integer.valueOf(-128) },
      new Object[] { Integer.valueOf(-129) },
      new Object[] { Integer.valueOf(-254) },
      new Object[] { Integer.valueOf(-255) },
      new Object[] { Integer.valueOf(-256) },
      new Object[] { Integer.valueOf(-257) },
      new Object[] { Integer.valueOf(-4094) },
      new Object[] { Integer.valueOf(-4095) },
      new Object[] { Integer.valueOf(-4096) },
      new Object[] { Integer.valueOf(-4097) },
      new Object[] { Integer.valueOf(-65534) },
      new Object[] { Integer.valueOf(-65535) },
      new Object[] { Integer.valueOf(-65536) },
      new Object[] { Integer.valueOf(-65537) },
      new Object[] { Integer.valueOf(-1048574) },
      new Object[] { Integer.valueOf(-1048575) },
      new Object[] { Integer.valueOf(-1048576) },
      new Object[] { Integer.valueOf(-1048577) },
      new Object[] { Integer.valueOf(-16777214) },
      new Object[] { Integer.valueOf(-16777215) },
      new Object[] { Integer.valueOf(-16777216) },
      new Object[] { Integer.valueOf(-16777217) },
      new Object[] { Integer.valueOf(-268435454) },
      new Object[] { Integer.valueOf(-268435455) },
      new Object[] { Integer.valueOf(-268435456) },
      new Object[] { Integer.valueOf(-268435457) },
      new Object[] { Integer.valueOf(Integer.MIN_VALUE) },
    };
  }



  /**
   * Retrieves a set of test long values.
   *
   * @return  A set of test long values.
   */
  @DataProvider(name = "testLongs")
  public Object[][] getTestLongs()
  {
    return new Object[][]
    {
      new Object[] { Long.valueOf(0L) },
      new Object[] { Long.valueOf(1L) },
      new Object[] { Long.valueOf(2L) },
      new Object[] { Long.valueOf(3L) },
      new Object[] { Long.valueOf(4L) },
      new Object[] { Long.valueOf(5L) },
      new Object[] { Long.valueOf(6L) },
      new Object[] { Long.valueOf(7L) },
      new Object[] { Long.valueOf(8L) },
      new Object[] { Long.valueOf(9L) },
      new Object[] { Long.valueOf(10L) },
      new Object[] { Long.valueOf(11L) },
      new Object[] { Long.valueOf(12L) },
      new Object[] { Long.valueOf(13L) },
      new Object[] { Long.valueOf(14L) },
      new Object[] { Long.valueOf(15L) },
      new Object[] { Long.valueOf(16L) },
      new Object[] { Long.valueOf(17L) },
      new Object[] { Long.valueOf(18L) },
      new Object[] { Long.valueOf(19L) },
      new Object[] { Long.valueOf(20L) },
      new Object[] { Long.valueOf(21L) },
      new Object[] { Long.valueOf(22L) },
      new Object[] { Long.valueOf(23L) },
      new Object[] { Long.valueOf(24L) },
      new Object[] { Long.valueOf(25L) },
      new Object[] { Long.valueOf(26L) },
      new Object[] { Long.valueOf(27L) },
      new Object[] { Long.valueOf(28L) },
      new Object[] { Long.valueOf(29L) },
      new Object[] { Long.valueOf(30L) },
      new Object[] { Long.valueOf(31L) },
      new Object[] { Long.valueOf(32L) },
      new Object[] { Long.valueOf(33L) },
      new Object[] { Long.valueOf(34L) },
      new Object[] { Long.valueOf(35L) },
      new Object[] { Long.valueOf(36L) },
      new Object[] { Long.valueOf(37L) },
      new Object[] { Long.valueOf(38L) },
      new Object[] { Long.valueOf(39L) },
      new Object[] { Long.valueOf(40L) },
      new Object[] { Long.valueOf(41L) },
      new Object[] { Long.valueOf(42L) },
      new Object[] { Long.valueOf(43L) },
      new Object[] { Long.valueOf(44L) },
      new Object[] { Long.valueOf(45L) },
      new Object[] { Long.valueOf(46L) },
      new Object[] { Long.valueOf(47L) },
      new Object[] { Long.valueOf(48L) },
      new Object[] { Long.valueOf(49L) },
      new Object[] { Long.valueOf(50L) },
      new Object[] { Long.valueOf(51L) },
      new Object[] { Long.valueOf(52L) },
      new Object[] { Long.valueOf(53L) },
      new Object[] { Long.valueOf(54L) },
      new Object[] { Long.valueOf(55L) },
      new Object[] { Long.valueOf(56L) },
      new Object[] { Long.valueOf(57L) },
      new Object[] { Long.valueOf(58L) },
      new Object[] { Long.valueOf(59L) },
      new Object[] { Long.valueOf(60L) },
      new Object[] { Long.valueOf(61L) },
      new Object[] { Long.valueOf(62L) },
      new Object[] { Long.valueOf(63L) },
      new Object[] { Long.valueOf(64L) },
      new Object[] { Long.valueOf(65L) },
      new Object[] { Long.valueOf(66L) },
      new Object[] { Long.valueOf(67L) },
      new Object[] { Long.valueOf(68L) },
      new Object[] { Long.valueOf(69L) },
      new Object[] { Long.valueOf(70L) },
      new Object[] { Long.valueOf(71L) },
      new Object[] { Long.valueOf(72L) },
      new Object[] { Long.valueOf(73L) },
      new Object[] { Long.valueOf(74L) },
      new Object[] { Long.valueOf(75L) },
      new Object[] { Long.valueOf(76L) },
      new Object[] { Long.valueOf(77L) },
      new Object[] { Long.valueOf(78L) },
      new Object[] { Long.valueOf(79L) },
      new Object[] { Long.valueOf(80L) },
      new Object[] { Long.valueOf(81L) },
      new Object[] { Long.valueOf(82L) },
      new Object[] { Long.valueOf(83L) },
      new Object[] { Long.valueOf(84L) },
      new Object[] { Long.valueOf(85L) },
      new Object[] { Long.valueOf(86L) },
      new Object[] { Long.valueOf(87L) },
      new Object[] { Long.valueOf(88L) },
      new Object[] { Long.valueOf(89L) },
      new Object[] { Long.valueOf(90L) },
      new Object[] { Long.valueOf(91L) },
      new Object[] { Long.valueOf(92L) },
      new Object[] { Long.valueOf(93L) },
      new Object[] { Long.valueOf(94L) },
      new Object[] { Long.valueOf(95L) },
      new Object[] { Long.valueOf(96L) },
      new Object[] { Long.valueOf(97L) },
      new Object[] { Long.valueOf(98L) },
      new Object[] { Long.valueOf(99L) },
      new Object[] { Long.valueOf(100L) },
      new Object[] { Long.valueOf(101L) },
      new Object[] { Long.valueOf(102L) },
      new Object[] { Long.valueOf(103L) },
      new Object[] { Long.valueOf(104L) },
      new Object[] { Long.valueOf(105L) },
      new Object[] { Long.valueOf(106L) },
      new Object[] { Long.valueOf(107L) },
      new Object[] { Long.valueOf(108L) },
      new Object[] { Long.valueOf(109L) },
      new Object[] { Long.valueOf(110L) },
      new Object[] { Long.valueOf(111L) },
      new Object[] { Long.valueOf(112L) },
      new Object[] { Long.valueOf(113L) },
      new Object[] { Long.valueOf(114L) },
      new Object[] { Long.valueOf(115L) },
      new Object[] { Long.valueOf(116L) },
      new Object[] { Long.valueOf(117L) },
      new Object[] { Long.valueOf(118L) },
      new Object[] { Long.valueOf(119L) },
      new Object[] { Long.valueOf(120L) },
      new Object[] { Long.valueOf(121L) },
      new Object[] { Long.valueOf(122L) },
      new Object[] { Long.valueOf(123L) },
      new Object[] { Long.valueOf(124L) },
      new Object[] { Long.valueOf(125L) },
      new Object[] { Long.valueOf(126L) },
      new Object[] { Long.valueOf(127L) },
      new Object[] { Long.valueOf(128L) },
      new Object[] { Long.valueOf(129L) },
      new Object[] { Long.valueOf(254L) },
      new Object[] { Long.valueOf(255L) },
      new Object[] { Long.valueOf(256L) },
      new Object[] { Long.valueOf(257L) },
      new Object[] { Long.valueOf(4094L) },
      new Object[] { Long.valueOf(4095L) },
      new Object[] { Long.valueOf(4096L) },
      new Object[] { Long.valueOf(4097L) },
      new Object[] { Long.valueOf(65534L) },
      new Object[] { Long.valueOf(65535L) },
      new Object[] { Long.valueOf(65536L) },
      new Object[] { Long.valueOf(65537L) },
      new Object[] { Long.valueOf(1048574L) },
      new Object[] { Long.valueOf(1048575L) },
      new Object[] { Long.valueOf(1048576L) },
      new Object[] { Long.valueOf(1048577L) },
      new Object[] { Long.valueOf(16777214L) },
      new Object[] { Long.valueOf(16777215L) },
      new Object[] { Long.valueOf(16777216L) },
      new Object[] { Long.valueOf(16777217L) },
      new Object[] { Long.valueOf(268435454L) },
      new Object[] { Long.valueOf(268435455L) },
      new Object[] { Long.valueOf(268435456L) },
      new Object[] { Long.valueOf(268435457L) },
      new Object[] { Long.valueOf(2147483646L) },
      new Object[] { Long.valueOf(2147483647L) },
      new Object[] { Long.valueOf(2147483648L) },
      new Object[] { Long.valueOf(2147483649L) },
      new Object[] { Long.valueOf(4294967294L) },
      new Object[] { Long.valueOf(4294967295L) },
      new Object[] { Long.valueOf(4294967296L) },
      new Object[] { Long.valueOf(4294967297L) },
      new Object[] { Long.valueOf(68719476734L) },
      new Object[] { Long.valueOf(68719476735L) },
      new Object[] { Long.valueOf(68719476736L) },
      new Object[] { Long.valueOf(68719476737L) },
      new Object[] { Long.valueOf(1099511627774L) },
      new Object[] { Long.valueOf(1099511627775L) },
      new Object[] { Long.valueOf(1099511627776L) },
      new Object[] { Long.valueOf(1099511627777L) },
      new Object[] { Long.valueOf(17592186044414L) },
      new Object[] { Long.valueOf(17592186044415L) },
      new Object[] { Long.valueOf(17592186044416L) },
      new Object[] { Long.valueOf(17592186044417L) },
      new Object[] { Long.valueOf(281474976710654L) },
      new Object[] { Long.valueOf(281474976710655L) },
      new Object[] { Long.valueOf(281474976710656L) },
      new Object[] { Long.valueOf(281474976710657L) },
      new Object[] { Long.valueOf(4503599627370494L) },
      new Object[] { Long.valueOf(4503599627370495L) },
      new Object[] { Long.valueOf(4503599627370496L) },
      new Object[] { Long.valueOf(4503599627370497L) },
      new Object[] { Long.valueOf(72057594037927934L) },
      new Object[] { Long.valueOf(72057594037927935L) },
      new Object[] { Long.valueOf(72057594037927936L) },
      new Object[] { Long.valueOf(72057594037927937L) },
      new Object[] { Long.valueOf(1152921504606846974L) },
      new Object[] { Long.valueOf(1152921504606846975L) },
      new Object[] { Long.valueOf(1152921504606846976L) },
      new Object[] { Long.valueOf(1152921504606846977L) },
      new Object[] { Long.valueOf(Long.MAX_VALUE) },
      new Object[] { Long.valueOf(-1L) },
      new Object[] { Long.valueOf(-2L) },
      new Object[] { Long.valueOf(-3L) },
      new Object[] { Long.valueOf(-4L) },
      new Object[] { Long.valueOf(-5L) },
      new Object[] { Long.valueOf(-6L) },
      new Object[] { Long.valueOf(-7L) },
      new Object[] { Long.valueOf(-8L) },
      new Object[] { Long.valueOf(-9L) },
      new Object[] { Long.valueOf(-10L) },
      new Object[] { Long.valueOf(-11L) },
      new Object[] { Long.valueOf(-12L) },
      new Object[] { Long.valueOf(-13L) },
      new Object[] { Long.valueOf(-14L) },
      new Object[] { Long.valueOf(-15L) },
      new Object[] { Long.valueOf(-16L) },
      new Object[] { Long.valueOf(-17L) },
      new Object[] { Long.valueOf(-18L) },
      new Object[] { Long.valueOf(-19L) },
      new Object[] { Long.valueOf(-20L) },
      new Object[] { Long.valueOf(-21L) },
      new Object[] { Long.valueOf(-22L) },
      new Object[] { Long.valueOf(-23L) },
      new Object[] { Long.valueOf(-24L) },
      new Object[] { Long.valueOf(-25L) },
      new Object[] { Long.valueOf(-26L) },
      new Object[] { Long.valueOf(-27L) },
      new Object[] { Long.valueOf(-28L) },
      new Object[] { Long.valueOf(-29L) },
      new Object[] { Long.valueOf(-30L) },
      new Object[] { Long.valueOf(-31L) },
      new Object[] { Long.valueOf(-32L) },
      new Object[] { Long.valueOf(-33L) },
      new Object[] { Long.valueOf(-34L) },
      new Object[] { Long.valueOf(-35L) },
      new Object[] { Long.valueOf(-36L) },
      new Object[] { Long.valueOf(-37L) },
      new Object[] { Long.valueOf(-38L) },
      new Object[] { Long.valueOf(-39L) },
      new Object[] { Long.valueOf(-40L) },
      new Object[] { Long.valueOf(-41L) },
      new Object[] { Long.valueOf(-42L) },
      new Object[] { Long.valueOf(-43L) },
      new Object[] { Long.valueOf(-44L) },
      new Object[] { Long.valueOf(-45L) },
      new Object[] { Long.valueOf(-46L) },
      new Object[] { Long.valueOf(-47L) },
      new Object[] { Long.valueOf(-48L) },
      new Object[] { Long.valueOf(-49L) },
      new Object[] { Long.valueOf(-50L) },
      new Object[] { Long.valueOf(-51L) },
      new Object[] { Long.valueOf(-52L) },
      new Object[] { Long.valueOf(-53L) },
      new Object[] { Long.valueOf(-54L) },
      new Object[] { Long.valueOf(-55L) },
      new Object[] { Long.valueOf(-56L) },
      new Object[] { Long.valueOf(-57L) },
      new Object[] { Long.valueOf(-58L) },
      new Object[] { Long.valueOf(-59L) },
      new Object[] { Long.valueOf(-60L) },
      new Object[] { Long.valueOf(-61L) },
      new Object[] { Long.valueOf(-62L) },
      new Object[] { Long.valueOf(-63L) },
      new Object[] { Long.valueOf(-64L) },
      new Object[] { Long.valueOf(-65L) },
      new Object[] { Long.valueOf(-66L) },
      new Object[] { Long.valueOf(-67L) },
      new Object[] { Long.valueOf(-68L) },
      new Object[] { Long.valueOf(-69L) },
      new Object[] { Long.valueOf(-70L) },
      new Object[] { Long.valueOf(-71L) },
      new Object[] { Long.valueOf(-72L) },
      new Object[] { Long.valueOf(-73L) },
      new Object[] { Long.valueOf(-74L) },
      new Object[] { Long.valueOf(-75L) },
      new Object[] { Long.valueOf(-76L) },
      new Object[] { Long.valueOf(-77L) },
      new Object[] { Long.valueOf(-78L) },
      new Object[] { Long.valueOf(-79L) },
      new Object[] { Long.valueOf(-80L) },
      new Object[] { Long.valueOf(-81L) },
      new Object[] { Long.valueOf(-82L) },
      new Object[] { Long.valueOf(-83L) },
      new Object[] { Long.valueOf(-84L) },
      new Object[] { Long.valueOf(-85L) },
      new Object[] { Long.valueOf(-86L) },
      new Object[] { Long.valueOf(-87L) },
      new Object[] { Long.valueOf(-88L) },
      new Object[] { Long.valueOf(-89L) },
      new Object[] { Long.valueOf(-90L) },
      new Object[] { Long.valueOf(-91L) },
      new Object[] { Long.valueOf(-92L) },
      new Object[] { Long.valueOf(-93L) },
      new Object[] { Long.valueOf(-94L) },
      new Object[] { Long.valueOf(-95L) },
      new Object[] { Long.valueOf(-96L) },
      new Object[] { Long.valueOf(-97L) },
      new Object[] { Long.valueOf(-98L) },
      new Object[] { Long.valueOf(-99L) },
      new Object[] { Long.valueOf(-100L) },
      new Object[] { Long.valueOf(-101L) },
      new Object[] { Long.valueOf(-102L) },
      new Object[] { Long.valueOf(-103L) },
      new Object[] { Long.valueOf(-104L) },
      new Object[] { Long.valueOf(-105L) },
      new Object[] { Long.valueOf(-106L) },
      new Object[] { Long.valueOf(-107L) },
      new Object[] { Long.valueOf(-108L) },
      new Object[] { Long.valueOf(-109L) },
      new Object[] { Long.valueOf(-110L) },
      new Object[] { Long.valueOf(-111L) },
      new Object[] { Long.valueOf(-112L) },
      new Object[] { Long.valueOf(-113L) },
      new Object[] { Long.valueOf(-114L) },
      new Object[] { Long.valueOf(-115L) },
      new Object[] { Long.valueOf(-116L) },
      new Object[] { Long.valueOf(-117L) },
      new Object[] { Long.valueOf(-118L) },
      new Object[] { Long.valueOf(-119L) },
      new Object[] { Long.valueOf(-120L) },
      new Object[] { Long.valueOf(-121L) },
      new Object[] { Long.valueOf(-122L) },
      new Object[] { Long.valueOf(-123L) },
      new Object[] { Long.valueOf(-124L) },
      new Object[] { Long.valueOf(-125L) },
      new Object[] { Long.valueOf(-126L) },
      new Object[] { Long.valueOf(-127L) },
      new Object[] { Long.valueOf(-128L) },
      new Object[] { Long.valueOf(-129L) },
      new Object[] { Long.valueOf(-254L) },
      new Object[] { Long.valueOf(-255L) },
      new Object[] { Long.valueOf(-256L) },
      new Object[] { Long.valueOf(-257L) },
      new Object[] { Long.valueOf(-4094L) },
      new Object[] { Long.valueOf(-4095L) },
      new Object[] { Long.valueOf(-4096L) },
      new Object[] { Long.valueOf(-4097L) },
      new Object[] { Long.valueOf(-65534L) },
      new Object[] { Long.valueOf(-65535L) },
      new Object[] { Long.valueOf(-65536L) },
      new Object[] { Long.valueOf(-65537L) },
      new Object[] { Long.valueOf(-1048574L) },
      new Object[] { Long.valueOf(-1048575L) },
      new Object[] { Long.valueOf(-1048576L) },
      new Object[] { Long.valueOf(-1048577L) },
      new Object[] { Long.valueOf(-16777214L) },
      new Object[] { Long.valueOf(-16777215L) },
      new Object[] { Long.valueOf(-16777216L) },
      new Object[] { Long.valueOf(-16777217L) },
      new Object[] { Long.valueOf(-268435454L) },
      new Object[] { Long.valueOf(-268435455L) },
      new Object[] { Long.valueOf(-268435456L) },
      new Object[] { Long.valueOf(-268435457L) },
      new Object[] { Long.valueOf(-2147483646L) },
      new Object[] { Long.valueOf(-2147483647L) },
      new Object[] { Long.valueOf(-2147483648L) },
      new Object[] { Long.valueOf(-2147483649L) },
      new Object[] { Long.valueOf(-4294967294L) },
      new Object[] { Long.valueOf(-4294967295L) },
      new Object[] { Long.valueOf(-4294967296L) },
      new Object[] { Long.valueOf(-4294967297L) },
      new Object[] { Long.valueOf(-68719476734L) },
      new Object[] { Long.valueOf(-68719476735L) },
      new Object[] { Long.valueOf(-68719476736L) },
      new Object[] { Long.valueOf(-68719476737L) },
      new Object[] { Long.valueOf(-1099511627774L) },
      new Object[] { Long.valueOf(-1099511627775L) },
      new Object[] { Long.valueOf(-1099511627776L) },
      new Object[] { Long.valueOf(-1099511627777L) },
      new Object[] { Long.valueOf(-17592186044414L) },
      new Object[] { Long.valueOf(-17592186044415L) },
      new Object[] { Long.valueOf(-17592186044416L) },
      new Object[] { Long.valueOf(-17592186044417L) },
      new Object[] { Long.valueOf(-281474976710654L) },
      new Object[] { Long.valueOf(-281474976710655L) },
      new Object[] { Long.valueOf(-281474976710656L) },
      new Object[] { Long.valueOf(-281474976710657L) },
      new Object[] { Long.valueOf(-4503599627370494L) },
      new Object[] { Long.valueOf(-4503599627370495L) },
      new Object[] { Long.valueOf(-4503599627370496L) },
      new Object[] { Long.valueOf(-4503599627370497L) },
      new Object[] { Long.valueOf(-72057594037927934L) },
      new Object[] { Long.valueOf(-72057594037927935L) },
      new Object[] { Long.valueOf(-72057594037927936L) },
      new Object[] { Long.valueOf(-72057594037927937L) },
      new Object[] { Long.valueOf(-1152921504606846974L) },
      new Object[] { Long.valueOf(-1152921504606846975L) },
      new Object[] { Long.valueOf(-1152921504606846976L) },
      new Object[] { Long.valueOf(-1152921504606846977L) },
      new Object[] { Long.valueOf(Long.MIN_VALUE) },
    };
  }



  /**
   * Retrieves a set of ASN.1 element arrays that can be used for testing
   * sequences and sets.
   *
   * @return  A set of ASN.1 element arrays that can be used for testing
   *          sequences and sets.
   */
  @DataProvider(name = "testElementArrays")
  public Object[][] getTestElementArrays()
  {
    return new Object[][]
    {
      new Object[]
      {
        null
      },

      new Object[]
      {
        new ASN1Element[0]
      },

      new Object[]
      {
        new ASN1Element[]
        {
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Element((byte) 0x00)
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Element((byte) 0x00, new byte[0])
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Element((byte) 0x00, new byte[126])
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Element((byte) 0x00, new byte[127])
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Element((byte) 0x00, new byte[128])
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Element((byte) 0x00, new byte[129])
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Element((byte) 0x00, new byte[65534])
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Element((byte) 0x00, new byte[65535])
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Element((byte) 0x00, new byte[65536])
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Element((byte) 0x00, new byte[65537])
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Boolean(true),
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Enumerated(0)
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Integer(0)
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Null()
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1OctetString()
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Sequence()
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Set()
        }
      },

      new Object[]
      {
        new ASN1Element[]
        {
          new ASN1Element((byte) 0x00),
          new ASN1Element((byte) 0x00, new byte[0]),
          new ASN1Element((byte) 0x00, new byte[126]),
          new ASN1Element((byte) 0x00, new byte[127]),
          new ASN1Element((byte) 0x00, new byte[128]),
          new ASN1Element((byte) 0x00, new byte[129]),
          new ASN1Element((byte) 0x00, new byte[65534]),
          new ASN1Element((byte) 0x00, new byte[65535]),
          new ASN1Element((byte) 0x00, new byte[65536]),
          new ASN1Element((byte) 0x00, new byte[65537]),
          new ASN1Boolean(true),
          new ASN1Enumerated(0),
          new ASN1Integer(0),
          new ASN1Null(),
          new ASN1OctetString(),
          new ASN1Sequence(),
          new ASN1Set()
        }
      },
    };
  }



  /**
   *
   */
  /**
   * Retrieves a set of collections of ASN.1 elements that can be used for
   * testing sequences and sets.
   *
   * @return  A set of collections of ASN.1 elements that can be used for
   *          testing sequences and sets.
   */
  @DataProvider(name = "testElementCollections")
  public Object[][] getTestElementCollections()
  {
    Object[][] elementArrays = getTestElementArrays();
    Object[][] elementCollections = new Object[elementArrays.length][1];

    for (int i=0; i < elementArrays.length; i++)
    {
      if (elementArrays[i][0] == null)
      {
        elementCollections[i][0] = null;
      }
      else
      {
        ASN1Element[] elementArray = (ASN1Element[]) elementArrays[i][0];
        ArrayList<ASN1Element> elementList =
             new ArrayList<ASN1Element>(elementArray.length);
        for (ASN1Element e : elementArray)
        {
          elementList.add(e);
        }
        elementCollections[i][0] = elementList;
      }
    }

    return elementCollections;
  }
}
