/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.json;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.ByteStringBuffer;



/**
 * This class provides a set of test cases for the {@code JSONString} class.
 */
public final class JSONStringTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for an empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyString()
         throws Exception
  {
    final JSONString s = new JSONString("");

    assertNotNull(s.stringValue());
    assertEquals(s.stringValue(), "");

    assertTrue(s.equals(new JSONString(""), false));
    assertTrue(s.equals(new JSONString(""), true));

    assertFalse(s.equals(new JSONString("foo"), false));
    assertFalse(s.equals(new JSONString("foo"), true));

    assertNotNull(s.toString());
    assertEquals(s.toString(), "\"\"");

    assertNotNull(s.toSingleLineString());
    assertEquals(s.toSingleLineString(), "\"\"");

    final StringBuilder toStringBuffer = new StringBuilder();
    s.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "\"\"");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    s.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "\"\"");

    assertNotNull(s.toNormalizedString());
    assertEquals(s.toNormalizedString(), "\"\"");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    s.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "\"\"");

    assertNotNull(s.toNormalizedString(true, true, true));
    assertEquals(s.toNormalizedString(true, true, true), "\"\"");

    assertNotNull(s.toNormalizedString(false, false, false));
    assertEquals(s.toNormalizedString(false, false, false), "\"\"");

    toNormalizedStringBuffer.setLength(0);
    s.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(), "\"\"");

    toNormalizedStringBuffer.setLength(0);
    s.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(), "\"\"");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    s.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"\"");

    jsonBuffer.clear();
    s.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":\"\"");
  }



  /**
   * Provides test coverage for a string containing only ASCII characters that
   * don't require any escaping.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testASCIIStringNoEscapes()
         throws Exception
  {
    final JSONString s = new JSONString("This is a test.");

    assertNotNull(s.stringValue());
    assertEquals(s.stringValue(), "This is a test.");

    assertTrue(s.equals(new JSONString("This is a test."), false));
    assertTrue(s.equals(new JSONString("This is a test."), true));

    assertFalse(s.equals(new JSONString("this is a test."), false));
    assertTrue(s.equals(new JSONString("this is a test."), true));

    assertFalse(s.equals(new JSONString("foo."), false));
    assertFalse(s.equals(new JSONString("foo."), true));

    assertNotNull(s.toString());
    assertEquals(s.toString(), "\"This is a test.\"");

    assertNotNull(s.toSingleLineString());
    assertEquals(s.toSingleLineString(), "\"This is a test.\"");

    final StringBuilder toStringBuffer = new StringBuilder();
    s.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "\"This is a test.\"");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    s.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "\"This is a test.\"");

    assertNotNull(s.toNormalizedString());
    assertEquals(s.toNormalizedString(), "\"this is a test.\"");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    s.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "\"this is a test.\"");

    assertNotNull(s.toNormalizedString(true, true, true));
    assertEquals(s.toNormalizedString(true, true, true), "\"this is a test.\"");

    assertNotNull(s.toNormalizedString(false, false, false));
    assertEquals(s.toNormalizedString(false, false, false),
         "\"This is a test.\"");

    toNormalizedStringBuffer.setLength(0);
    s.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(), "\"this is a test.\"");

    toNormalizedStringBuffer.setLength(0);
    s.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(), "\"This is a test.\"");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    s.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"This is a test.\"");

    jsonBuffer.clear();
    s.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":\"This is a test.\"");
  }



  /**
   * Provides test coverage for a string containing a lot of characters that
   * need to be escaped.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLotsOfEscapes()
         throws Exception
  {
    final JSONString s = new JSONString("This \" string \\ has \u0000 " +
         "characters \b that \f need \n to \r be \t escaped.");

    assertNotNull(s.stringValue());
    assertEquals(s.stringValue(),
         "This \" string \\ has \u0000 characters \b that \f need \n to \r " +
              "be \t escaped.");

    assertTrue(s.equals(
         new JSONString("This \" string \\ has \u0000 characters \b that \f " +
              "need \n to \r be \t escaped."),
         false));
    assertTrue(s.equals(
         new JSONString("This \" string \\ has \u0000 characters \b that \f " +
              "need \n to \r be \t escaped."),
         true));

    assertFalse(s.equals(
         new JSONString("this \" string \\ has \u0000 characters \b that \f " +
              "need \n to \r be \t escaped."),
         false));
    assertTrue(s.equals(
         new JSONString("this \" string \\ has \u0000 characters \b that \f " +
              "need \n to \r be \t escaped."),
         true));

    assertFalse(s.equals(
         new JSONString("THIS \" STRING \\ HAS \u0000 CHARACTERS \b THAT \f " +
              "NEED \n TO \r BE \t ESCAPED."),
         false));
    assertTrue(s.equals(
         new JSONString("THIS \" STRING \\ HAS \u0000 CHARACTERS \b THAT \f " +
              "NEED \n TO \r BE \t ESCAPED."),
         true));

    assertFalse(s.equals(new JSONString("foo."), false));
    assertFalse(s.equals(new JSONString("foo."), true));

    assertNotNull(s.toString());
    assertEquals(s.toString(),
         "\"This \\\" string \\\\ has \\u0000 characters \\b that \\f need " +
              "\\n to \\r be \\t escaped.\"");

    assertNotNull(s.toSingleLineString());
    assertEquals(s.toSingleLineString(),
         "\"This \\\" string \\\\ has \\u0000 characters \\b that \\f need " +
              "\\n to \\r be \\t escaped.\"");

    final StringBuilder toStringBuffer = new StringBuilder();
    s.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(),
         "\"This \\\" string \\\\ has \\u0000 characters \\b that \\f need " +
              "\\n to \\r be \\t escaped.\"");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    s.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(),
         "\"This \\\" string \\\\ has \\u0000 characters \\b that \\f need " +
              "\\n to \\r be \\t escaped.\"");

    assertNotNull(s.toNormalizedString());
    assertEquals(s.toNormalizedString(),
         "\"this \\u0022 string \\u005C has \\u0000 characters \\u0008 that " +
              "\\u000C need \\u000A to \\u000D be \\u0009 escaped.\"");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    s.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(),
         "\"this \\u0022 string \\u005C has \\u0000 characters \\u0008 that " +
              "\\u000C need \\u000A to \\u000D be \\u0009 escaped.\"");

    assertNotNull(s.toNormalizedString(true, true, true));
    assertEquals(s.toNormalizedString(true, true, true),
         "\"this \\u0022 string \\u005C has \\u0000 characters \\u0008 that " +
              "\\u000C need \\u000A to \\u000D be \\u0009 escaped.\"");

    assertNotNull(s.toNormalizedString(false, false, false));
    assertEquals(s.toNormalizedString(false, false, false),
         "\"This \\u0022 string \\u005C has \\u0000 characters \\u0008 that " +
              "\\u000C need \\u000A to \\u000D be \\u0009 escaped.\"");

    toNormalizedStringBuffer.setLength(0);
    s.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(),
         "\"this \\u0022 string \\u005C has \\u0000 characters \\u0008 that " +
              "\\u000C need \\u000A to \\u000D be \\u0009 escaped.\"");

    toNormalizedStringBuffer.setLength(0);
    s.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(),
         "\"This \\u0022 string \\u005C has \\u0000 characters \\u0008 that " +
              "\\u000C need \\u000A to \\u000D be \\u0009 escaped.\"");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    s.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(),
         "\"This \\\" string \\\\ has \\u0000 characters \\b that \\f need " +
              "\\n to \\r be \\t escaped.\"");

    jsonBuffer.clear();
    s.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(),
         "\"fieldName\":\"This \\\" string \\\\ has \\u0000 characters \\b " +
              "that \\f need \\n to \\r be \\t escaped.\"");
  }



  /**
   * Provides test coverage for a string containing non-ASCII characters that
   * are escaped.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonASCIIEscapes()
         throws Exception
  {
    final JSONString s = new JSONString("Jos\u00e9 Jalape\u00f1o");

    assertNotNull(s.stringValue());
    assertEquals(s.stringValue(), "Jos\u00e9 Jalape\u00f1o");

    assertTrue(s.equals(new JSONString("Jos\u00e9 Jalape\u00f1o"), false));
    assertTrue(s.equals(new JSONString("Jos\u00e9 Jalape\u00f1o"), true));

    assertFalse(s.equals(new JSONString("jos\u00e9 jalape\u00f1o"), false));
    assertTrue(s.equals(new JSONString("jos\u00e9 jalape\u00f1o"), true));

    assertFalse(s.equals(new JSONString("foo."), false));
    assertFalse(s.equals(new JSONString("foo."), true));

    assertNotNull(s.toString());
    assertEquals(s.toString(), "\"Jos\u00e9 Jalape\u00f1o\"");

    assertNotNull(s.toSingleLineString());
    assertEquals(s.toSingleLineString(), "\"Jos\u00e9 Jalape\u00f1o\"");

    final StringBuilder toStringBuffer = new StringBuilder();
    s.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "\"Jos\u00e9 Jalape\u00f1o\"");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    s.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(),
         "\"Jos\u00e9 Jalape\u00f1o\"");

    assertNotNull(s.toNormalizedString());
    assertEquals(s.toNormalizedString(), "\"jos\\u00E9 jalape\\u00F1o\"");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    s.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(),
         "\"jos\\u00E9 jalape\\u00F1o\"");

    assertNotNull(s.toNormalizedString(true, true, true));
    assertEquals(s.toNormalizedString(true, true, true),
         "\"jos\\u00E9 jalape\\u00F1o\"");

    assertNotNull(s.toNormalizedString(false, false, false));
    assertEquals(s.toNormalizedString(false, false, false),
         "\"Jos\\u00E9 Jalape\\u00F1o\"");

    toNormalizedStringBuffer.setLength(0);
    s.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(),
         "\"jos\\u00E9 jalape\\u00F1o\"");

    toNormalizedStringBuffer.setLength(0);
    s.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(),
         "\"Jos\\u00E9 Jalape\\u00F1o\"");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    s.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(),
         "\"Jos\u00e9 Jalape\u00f1o\"");

    jsonBuffer.clear();
    s.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(),
         "\"fieldName\":\"Jos\u00e9 Jalape\u00f1o\"");
  }



  /**
   * Tests the {@code equals} method for equality with the same object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    final JSONString s1 = new JSONString("");
    assertTrue(s1.equals(s1));
    assertEquals(s1.hashCode(), s1.hashCode());

    final JSONString s2 = new JSONString("This is a test.");
    assertTrue(s2.equals(s2));
    assertEquals(s2.hashCode(), s2.hashCode());

    final JSONString s3 = new JSONString("This \" string \\ has / characters " +
         "\b that \f need \n to \r be \t escaped.");
    assertTrue(s3.equals(s3));
    assertEquals(s3.hashCode(), s3.hashCode());

    final JSONString s4 = new JSONString("Jos\u00e9 Jalape\u00f1o");
    assertTrue(s4.equals(s4));
    assertEquals(s4.hashCode(), s4.hashCode());
  }



  /**
   * Tests the {@code equals} method for equality with an equivalent object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalent()
         throws Exception
  {
    final JSONString s1a = new JSONString("");
    final JSONString s1b = new JSONString("");
    assertTrue(s1a.equals(s1b));
    assertEquals(s1a.hashCode(), s1b.hashCode());

    final JSONString s2a = new JSONString("This is a test.");
    final JSONString s2b = new JSONString("This is a test.");
    assertTrue(s2a.equals(s2b));
    assertEquals(s2a.hashCode(), s2b.hashCode());

    final JSONString s3a = new JSONString("This \" string \\ has / " +
         "characters \b that \f need \n to \r be \t escaped.");
    final JSONString s3b = new JSONString("This \" string \\ has / " +
         "characters \b that \f need \n to \r be \t escaped.");
    assertTrue(s3a.equals(s3b));
    assertEquals(s3a.hashCode(), s3b.hashCode());

    final JSONString s4a = new JSONString("Jos\u00e9 Jalape\u00f1o");
    final JSONString s4b = new JSONString("Jos\u00e9 Jalape\u00f1o");
    assertTrue(s4a.equals(s4b));
    assertEquals(s4a.hashCode(), s4b.hashCode());
  }



  /**
   * Tests the {@code equals} method for equality with a non-equivalent object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotEquivalent()
         throws Exception
  {
    final JSONString s1 = new JSONString("");
    final JSONString s2 = new JSONString("foo");

    assertFalse(s1.equals(s2));
    assertFalse(s2.equals(s1));

    final JSONString s3 = new JSONString("Foo");

    assertFalse(s2.equals(s3));
    assertFalse(s3.equals(s2));
  }



  /**
   * Tests the {@code equals} method for equality with a {@code null} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    final JSONString s1 = new JSONString("");

    assertFalse(s1.equals(null));

    final JSONString s2 = null;
    assertFalse(s1.equals(s2));

    final String s = null;
    assertFalse(s1.equals(s));
  }



  /**
   * Tests the {@code equals} method for an object that isn't a
   * {@code JSONString} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentTypeOfObject()
         throws Exception
  {
    final JSONString s = new JSONString("");

    assertFalse(s.equals("foo"));

    assertFalse(s.equals(""));

    assertFalse(s.equals(JSONBoolean.TRUE));
  }



  /**
   * Provides test coverage for the {@code encodeString} method that appends to
   * a {@code StringBuilder}.
   *
   * @param  toEncode         The string to encode.
   * @param  expectedEncoded  The expected encoded string representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "encodeData")
  public void testEncodeStringToStringBuilder(final String toEncode,
                                              final String expectedEncoded)
         throws Exception
  {
    final StringBuilder buffer = new StringBuilder();
    JSONString.encodeString(toEncode, buffer);
    assertEquals(buffer.toString(), expectedEncoded);
  }



  /**
   * Provides test coverage for the {@code encodeString} method that appends to
   * a {@code StringBuilder}.
   *
   * @param  toEncode         The string to encode.
   * @param  expectedEncoded  The expected encoded string representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "encodeData")
  public void testEncodeStringToByteStringBuffer(final String toEncode,
                                                 final String expectedEncoded)
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    JSONString.encodeString(toEncode, buffer);
    assertEquals(buffer.toString(), expectedEncoded);
  }



  /**
   * Retrieves a set of data for testing the {@code encodeString} methods.
   *
   * @return  A set of data for testing the {@code encodeString} methods.
   */
  @DataProvider(name="encodeData")
  public Object[][] getEncodeData()
  {
    return new Object[][]
    {
      new Object[]
      {
        "",
        "\"\"",
      },

      new Object[]
      {
        "a",
        "\"a\"",
      },

      new Object[]
      {
        "abcdefghijklmnopqrstuvwxyz",
        "\"abcdefghijklmnopqrstuvwxyz\"",
      },

      new Object[]
      {
        "quote\"backslash\\backspace\bformfeed\fnewline\nreturn\r" +
             "tab\tnull\u0000",
        "\"quote\\\"backslash\\\\backspace\\bformfeed\\fnewline\\nreturn\\r" +
             "tab\\tnull\\u0000\"",
      }
    };
  }



  /**
   * Tests the {@code equals} method that takes an extended set of arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsExtended()
         throws Exception
  {
    final JSONString s1 = new JSONString("foo");
    final JSONString s2 = new JSONString("Foo");
    final JSONString s3 = new JSONString("bar");

    assertTrue(s1.equals(s1, true, true, true));
    assertTrue(s1.equals(s1, false, false, false));

    assertTrue(s1.equals(s2, true, true, true));
    assertFalse(s1.equals(s2, false, false, false));

    assertFalse(s1.equals(s3, true, true, true));
    assertFalse(s1.equals(s3, false, false, false));
  }
}
