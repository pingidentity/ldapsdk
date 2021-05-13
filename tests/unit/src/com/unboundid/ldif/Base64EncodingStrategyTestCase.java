/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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
package com.unboundid.ldif;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the {@code Base64EncodingStrategy}
 * class.
 */
public final class Base64EncodingStrategyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for the default strategy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultStrategy()
         throws Exception
  {
    final Base64EncodingStrategy strategy = Base64EncodingStrategy.DEFAULT;
    assertNotNull(strategy);

    assertTrue(strategy.encodeASCIIControlCharacters());

    assertFalse(strategy.encodeDisplayableNonASCIICharacters());

    assertTrue(strategy.encodeNonDisplayableNonASCIICharacters());

    assertTrue(strategy.encodeNonUTF8Data());

    assertNotNull(strategy.toString());

    for (final String s : getAlwaysEncodeStrings())
    {
      assertTrue(strategy.shouldBase64Encode(s));
      assertTrue(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertTrue(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getNeverEncodeStrings())
    {
      assertFalse(strategy.shouldBase64Encode(s));
      assertFalse(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertFalse(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getControlCharacterStrings())
    {
      assertTrue(strategy.shouldBase64Encode(s));
      assertTrue(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertTrue(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getDisplayableNonASCIICharacterStrings())
    {
      assertFalse(strategy.shouldBase64Encode(s));
      assertFalse(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertFalse(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getNonDisplayableNonASCIICharacterStrings())
    {
      assertTrue(strategy.shouldBase64Encode(s));
      assertTrue(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertTrue(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final byte[] b : getNonUTF8DataByteArrays())
    {
      assertTrue(strategy.shouldBase64Encode(b));
      assertTrue(strategy.shouldBase64Encode(new ASN1OctetString(b)));
    }
  }



  /**
   * Tests the behavior for the minimal strategy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalStrategy()
         throws Exception
  {
    final Base64EncodingStrategy strategy = Base64EncodingStrategy.MINIMAL;
    assertNotNull(strategy);

    assertFalse(strategy.encodeASCIIControlCharacters());

    assertFalse(strategy.encodeDisplayableNonASCIICharacters());

    assertFalse(strategy.encodeNonDisplayableNonASCIICharacters());

    assertFalse(strategy.encodeNonUTF8Data());

    assertNotNull(strategy.toString());

    for (final String s : getAlwaysEncodeStrings())
    {
      assertTrue(strategy.shouldBase64Encode(s));
      assertTrue(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertTrue(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getNeverEncodeStrings())
    {
      assertFalse(strategy.shouldBase64Encode(s));
      assertFalse(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertFalse(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getControlCharacterStrings())
    {
      assertFalse(strategy.shouldBase64Encode(s));
      assertFalse(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertFalse(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getDisplayableNonASCIICharacterStrings())
    {
      assertFalse(strategy.shouldBase64Encode(s));
      assertFalse(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertFalse(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getNonDisplayableNonASCIICharacterStrings())
    {
      assertFalse(strategy.shouldBase64Encode(s));
      assertFalse(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertFalse(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final byte[] b : getNonUTF8DataByteArrays())
    {
      assertFalse(strategy.shouldBase64Encode(b));
      assertFalse(strategy.shouldBase64Encode(new ASN1OctetString(b)));
    }
  }



  /**
   * Tests the behavior for the maximal strategy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaximalStrategy()
         throws Exception
  {
    final Base64EncodingStrategy strategy = Base64EncodingStrategy.MAXIMAL;
    assertNotNull(strategy);

    assertTrue(strategy.encodeASCIIControlCharacters());

    assertTrue(strategy.encodeDisplayableNonASCIICharacters());

    assertTrue(strategy.encodeNonDisplayableNonASCIICharacters());

    assertTrue(strategy.encodeNonUTF8Data());

    assertNotNull(strategy.toString());

    for (final String s : getAlwaysEncodeStrings())
    {
      assertTrue(strategy.shouldBase64Encode(s));
      assertTrue(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertTrue(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getNeverEncodeStrings())
    {
      assertFalse(strategy.shouldBase64Encode(s));
      assertFalse(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertFalse(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getControlCharacterStrings())
    {
      assertTrue(strategy.shouldBase64Encode(s));
      assertTrue(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertTrue(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getDisplayableNonASCIICharacterStrings())
    {
      assertTrue(strategy.shouldBase64Encode(s));
      assertTrue(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertTrue(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final String s : getNonDisplayableNonASCIICharacterStrings())
    {
      assertTrue(strategy.shouldBase64Encode(s));
      assertTrue(strategy.shouldBase64Encode(StaticUtils.getBytes(s)));
      assertTrue(strategy.shouldBase64Encode(new ASN1OctetString(s)));
    }

    for (final byte[] b : getNonUTF8DataByteArrays())
    {
      assertTrue(strategy.shouldBase64Encode(b));
      assertTrue(strategy.shouldBase64Encode(new ASN1OctetString(b)));
    }
  }



  /**
   * Retrieves a set of strings that should always be base64-encoded.
   *
   * @return  A set of strings that should always be base64-encoded.
   */
  private String[] getAlwaysEncodeStrings()
  {
    return new String[]
    {
      " ",
      " leading space",
      ":",
      ":leading colon",
      "<",
      "<leading less-than",
      "trailing space ",
      "\u0000leading ASCII null",
      "middle\u0000ASCII\u0000null",
      "trailing ASCII null\u0000",
      "\nleading line feed",
      "middle\nline\nfeed",
      "trailing line feed\n",
      "\rleading carriage return",
      "middle\rcarriage\rreturn",
      "trailing carriage return\r"
    };
  }



  /**
   * Retrieves a set of strings that should never be base64-encoded.
   *
   * @return  A set of strings that should never be base64-encoded.
   */
  private String[] getNeverEncodeStrings()
  {
    return new String[]
    {
      "",
      "a",
      "A",
      "1",
      "!",
      "a b c d",
      "a b c d ~ e f g h",
      "a!A1",
    };
  }



  /**
   * Retrieves a set of strings that contain control characters.
   *
   * @return  A set of strings that contain control characters.
   */
  private String[] getControlCharacterStrings()
  {
    return new String[]
    {
      "\u0001a",
      "a\u0002b",
      "a\u0003",
      "a\u0004b",
      "a\u0005b",
      "a\u0006b",
      "a\u0007b",
      "a\u0008b",
      "a\u0009b",
      "a\u000Bb",
      "a\u000Cb",
      "a\u000Eb",
      "a\u000Fb",
      "a\u0010b",
      "a\u0011b",
      "a\u0012b",
      "a\u0013b",
      "a\u0014b",
      "a\u0015b",
      "a\u0016b",
      "a\u0017b",
      "a\u0018b",
      "a\u0019b",
      "a\u001Ab",
      "a\u001Bb",
      "a\u001Cb",
      "a\u001Db",
      "a\u001Eb",
      "a\u001Fb",
      "a\u007Fb",
    };
  }



  /**
   * Retrieves a set of strings that contain displayable non-ASCII characters.
   *
   * @return  A set of strings that contain displayable non-ASCII characters.
   */
  private String[] getDisplayableNonASCIICharacterStrings()
  {
    return new String[]
    {
      "jalape\u00f1o",
      "\u00f1leading",
      "trailing\u00f1"
    };
  }



  /**
   * Retrieves a set of strings that contain non-displayable non-ASCII
   * characters.
   *
   * @return  A set of strings that contain non-displayable non-ASCII
   *          characters.
   */
  private String[] getNonDisplayableNonASCIICharacterStrings()
  {
    return new String[]
    {
      "a\u0488b",
      "\u0488leading",
      "trailing\u0488"
    };
  }



  /**
   * Retrieves a set of byte arrays that contain non-UTF-8 data.
   *
   * @return  A set of byte arrays that contain non-UTF-8 data.
   */
  private byte[][] getNonUTF8DataByteArrays()
  {
    return new byte[][]
    {
      StaticUtils.byteArray(0x80),
      StaticUtils.byteArray(0xC0),
      StaticUtils.byteArray('a', 0x80),
      StaticUtils.byteArray(0x80, 'b'),
      StaticUtils.byteArray('a', 0x80, 'b')
    };
  }
}
