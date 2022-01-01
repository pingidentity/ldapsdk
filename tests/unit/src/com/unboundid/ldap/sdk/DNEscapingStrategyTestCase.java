/*
 * Copyright 2021-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2022 Ping Identity Corporation
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
 * Copyright (C) 2021-2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the {@code DNEscapingStrategy} class.
 */
public final class DNEscapingStrategyTestCase
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
    final DNEscapingStrategy strategy = DNEscapingStrategy.DEFAULT;
    assertNotNull(strategy);

    assertTrue(strategy.escapeASCIIControlCharacters());

    assertFalse(strategy.escapeDisplayableNonASCIICharacters());

    assertTrue(strategy.escapeNonDisplayableNonASCIICharacters());

    assertTrue(strategy.escapeNonUTF8Data());

    assertNotNull(strategy.toString());

    final ByteStringBuffer buffer = new ByteStringBuffer();
    for (final Map.Entry<String,String> e : getAlwaysEscapeStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());
    }

    for (final String s : getNeverEscapeStrings())
    {
      buffer.clear();
      strategy.escape(s, buffer);
      assertEquals(buffer.toString(), s);

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(s), buffer);
      assertEquals(buffer.toString(), s);

      buffer.clear();
      strategy.escape(new ASN1OctetString(s), buffer);
      assertEquals(buffer.toString(), s);
    }

    for (final Map.Entry<String,String> e :
         getControlCharacterStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());
    }

    for (final Map.Entry<String,String> e :
         getDisplayableNonASCIICharacterStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getKey());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getKey());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getKey());
    }

    for (final Map.Entry<String,String> e :
         getNonDisplayableNonASCIICharacterStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());
    }

    for (final Map.Entry<byte[],String> e : getNonUTF8Data().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());
    }
  }



  /**
   * Tests the behavior for the minimal escaping strategy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalStrategy()
         throws Exception
  {
    final DNEscapingStrategy strategy = DNEscapingStrategy.MINIMAL;
    assertNotNull(strategy);

    assertFalse(strategy.escapeASCIIControlCharacters());

    assertFalse(strategy.escapeDisplayableNonASCIICharacters());

    assertFalse(strategy.escapeNonDisplayableNonASCIICharacters());

    assertFalse(strategy.escapeNonUTF8Data());

    assertNotNull(strategy.toString());

    final ByteStringBuffer buffer = new ByteStringBuffer();
    for (final Map.Entry<String,String> e : getAlwaysEscapeStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());
    }

    for (final String s : getNeverEscapeStrings())
    {
      buffer.clear();
      strategy.escape(s, buffer);
      assertEquals(buffer.toString(), s);

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(s), buffer);
      assertEquals(buffer.toString(), s);

      buffer.clear();
      strategy.escape(new ASN1OctetString(s), buffer);
      assertEquals(buffer.toString(), s);
    }

    for (final Map.Entry<String,String> e :
         getControlCharacterStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getKey());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getKey());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getKey());
    }

    for (final Map.Entry<String,String> e :
         getDisplayableNonASCIICharacterStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getKey());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getKey());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getKey());
    }

    for (final Map.Entry<String,String> e :
         getNonDisplayableNonASCIICharacterStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getKey());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getKey());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getKey());
    }

    for (final Map.Entry<byte[],String> e : getNonUTF8Data().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toByteArray(), e.getKey());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toByteArray(), e.getKey());
    }
  }



  /**
   * Tests the behavior for the maximal escaping strategy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaximalStrategy()
         throws Exception
  {
    final DNEscapingStrategy strategy = DNEscapingStrategy.MAXIMAL;
    assertNotNull(strategy);

    assertTrue(strategy.escapeASCIIControlCharacters());

    assertTrue(strategy.escapeDisplayableNonASCIICharacters());

    assertTrue(strategy.escapeNonDisplayableNonASCIICharacters());

    assertTrue(strategy.escapeNonUTF8Data());

    assertNotNull(strategy.toString());

    final ByteStringBuffer buffer = new ByteStringBuffer();
    for (final Map.Entry<String,String> e : getAlwaysEscapeStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());
    }

    for (final String s : getNeverEscapeStrings())
    {
      buffer.clear();
      strategy.escape(s, buffer);
      assertEquals(buffer.toString(), s);

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(s), buffer);
      assertEquals(buffer.toString(), s);

      buffer.clear();
      strategy.escape(new ASN1OctetString(s), buffer);
      assertEquals(buffer.toString(), s);
    }

    for (final Map.Entry<String,String> e :
         getControlCharacterStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());
    }

    for (final Map.Entry<String,String> e :
         getDisplayableNonASCIICharacterStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());
    }

    for (final Map.Entry<String,String> e :
         getNonDisplayableNonASCIICharacterStrings().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(StaticUtils.getBytes(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());
    }

    for (final Map.Entry<byte[],String> e : getNonUTF8Data().entrySet())
    {
      buffer.clear();
      strategy.escape(e.getKey(), buffer);
      assertEquals(buffer.toString(), e.getValue());

      buffer.clear();
      strategy.escape(new ASN1OctetString(e.getKey()), buffer);
      assertEquals(buffer.toString(), e.getValue());
    }
  }



  /**
   * Retrieves a map of strings that should always include some escaping.  The
   * key of the map will be the unescaped strings, and the value should be the
   * escaped representation.
   *
   * @return  A map of strings that should always include some escaping.
   */
  private Map<String,String> getAlwaysEscapeStrings()
  {
    return StaticUtils.mapOf(
         " ", "\\ ",
         " leading space", "\\ leading space",
         "trailing space ", "trailing space\\ ",
         "trailing space ", "trailing space\\ ",
         "   multiple  leading   and  trailing spaces   ",
              "\\   multiple  leading   and  trailing spaces  \\ ",
         "#", "\\#",
         "# leading octothorpe", "\\# leading octothorpe",
         "\"string\"with\"quotes\"", "\\\"string\\\"with\\\"quotes\\\"",
         "+string+with+plus+", "\\+string\\+with\\+plus\\+",
         ",string,with,commas,", "\\,string\\,with\\,commas\\,",
         ";string;with;semicolons;", "\\;string\\;with\\;semicolons\\;",
         "<string<with>inequality>", "\\<string\\<with\\>inequality\\>",
         "\\string\\with\\backslashes\\",
              "\\\\string\\\\with\\\\backslashes\\\\",
         "\u0000string\u0000with\u0000nulls\u0000",
              "\\00string\\00with\\00nulls\\00");
  }



  /**
   * Retrieves an array of strings that should never require any escaping.
   *
   * @return  an array of strings that should never be escaped.
   */
  private String[] getNeverEscapeStrings()
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
   * Retrieves a map of strings that contain ASCII control characters that might
   * need to be escaped.  The key of the map will be the unescaped strings, and
   * the value should be the escaped representation.
   *
   * @return  A map of strings that contain ASCII control characters.
   */
  private Map<String,String> getControlCharacterStrings()
  {
    return StaticUtils.mapOf(
         // NOTE:  The NULL control character must always be escaped.
         "\u0001a\u0001b\u0001", "\\01a\\01b\\01",
         "\u0002a\u0002b\u0002", "\\02a\\02b\\02",
         "\u0003a\u0003b\u0003", "\\03a\\03b\\03",
         "\u0004a\u0004b\u0004", "\\04a\\04b\\04",
         "\u0005a\u0005b\u0005", "\\05a\\05b\\05",
         "\u0006a\u0006b\u0006", "\\06a\\06b\\06",
         "\u0007a\u0007b\u0007", "\\07a\\07b\\07",
         "\u0008a\u0008b\u0008", "\\08a\\08b\\08",
         "\u0009a\u0009b\u0009", "\\09a\\09b\\09",
         "\na\nb\n",             "\\0aa\\0ab\\0a",
         "\u000Ba\u000Bb\u000B", "\\0ba\\0bb\\0b",
         "\u000Ca\u000Cb\u000C", "\\0ca\\0cb\\0c",
         "\ra\rb\r",             "\\0da\\0db\\0d",
         "\u000Ea\u000Eb\u000E", "\\0ea\\0eb\\0e",
         "\u000Fa\u000Fb\u000F", "\\0fa\\0fb\\0f",

         "\u0010a\u0010b\u0010", "\\10a\\10b\\10",
         "\u0011a\u0011b\u0011", "\\11a\\11b\\11",
         "\u0012a\u0012b\u0012", "\\12a\\12b\\12",
         "\u0013a\u0013b\u0013", "\\13a\\13b\\13",
         "\u0014a\u0014b\u0014", "\\14a\\14b\\14",
         "\u0015a\u0015b\u0015", "\\15a\\15b\\15",
         "\u0016a\u0016b\u0016", "\\16a\\16b\\16",
         "\u0017a\u0017b\u0017", "\\17a\\17b\\17",
         "\u0018a\u0018b\u0018", "\\18a\\18b\\18",
         "\u0019a\u0019b\u0019", "\\19a\\19b\\19",
         "\u001Aa\u001Ab\u001A", "\\1aa\\1ab\\1a",
         "\u001Ba\u001Bb\u001B", "\\1ba\\1bb\\1b",
         "\u001Ca\u001Cb\u001C", "\\1ca\\1cb\\1c",
         "\u001Da\u001Db\u001D", "\\1da\\1db\\1d",
         "\u001Ea\u001Eb\u001E", "\\1ea\\1eb\\1e",
         "\u001Fa\u001Fb\u001F", "\\1fa\\1fb\\1f",

         "\u007Fa\u007Fb\u007F", "\\7fa\\7fb\\7f");
  }



  /**
   * Retrieves a map of strings that contain displayable non-ASCII characters
   * that might need to be escaped.  The key of the map will be the unescaped
   * strings, and the value should be the escaped representation.
   *
   * @return  A map of strings that contain displayable non-ASCII characters.
   */
  private Map<String,String> getDisplayableNonASCIICharacterStrings()
  {
    return StaticUtils.mapOf(
         "jalape\u00f1o", "jalape\\c3\\b1o",
         "\u00f1leading", "\\c3\\b1leading",
         "trailing\u00f1", "trailing\\c3\\b1");
  }



  /**
   * Retrieves a map of strings that contain non-displayable non-ASCII
   * characters that might need to be escaped.  The key of the map will be the
   * unescaped strings, and the value should be the escaped representation.
   *
   * @return  A map of strings that contain non-displayable non-ASCII
   *          characters.
   */
  private Map<String,String> getNonDisplayableNonASCIICharacterStrings()
  {
    return StaticUtils.mapOf(
         "a\u0488b", "a\\d2\\88b",
         "\u0488leading", "\\d2\\88leading",
         "trailing\u0488", "trailing\\d2\\88");
  }



  /**
   * Retrieves a map of byte arrays that contain non-UTF-8 data that might need
   * to be escaped, along with the escaped string representations.
   *
   * @return  A map of byte arrays that contain non-UTF-8 data.
   */
  private Map<byte[],String> getNonUTF8Data()
  {
    return StaticUtils.mapOf(
         StaticUtils.byteArray(0x80), "\\80",
         StaticUtils.byteArray(0xC0), "\\c0",
         StaticUtils.byteArray('a', 0x80), "a\\80",
         StaticUtils.byteArray(0x80, 'b'), "\\80b",
         StaticUtils.byteArray('a', 0x80, 'b'), "a\\80b");
  }
}
