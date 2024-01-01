/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
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
 * Copyright (C) 2022-2024 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the log field syntax base class.
 */
public final class LogFieldSyntaxTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the method used to get the maximum string
   * length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaxStringLength()
         throws Exception
  {
    for (int i=0; i < 10; i++)
    {
      final StringLogFieldSyntax syntax =
           new StringLogFieldSyntax(i);
      assertEquals(syntax.getMaxStringLengthCharacters(), i);
    }

  }



  /**
   * Provides test coverage for the valueToSanitizedString method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueToSanitizedString()
         throws Exception
  {
    final StringLogFieldSyntax syntax = new StringLogFieldSyntax(10);


    // Test a value that doesn't require any sanitization.
    assertNotNull(syntax.valueToSanitizedString("test"));
    assertEquals(syntax.valueToSanitizedString("test"), "test");


    // Test a value that is more than one character longer than the maximum
    // length.
    assertNotNull(syntax.valueToSanitizedString("it's a test"));
    assertEquals(syntax.valueToSanitizedString("it's a test"),
         "it's a tes{1 more character}");


    // Test a value that is more than one character longer than the maximum
    // length.
    assertNotNull(syntax.valueToSanitizedString("this is a test"));
    assertEquals(syntax.valueToSanitizedString("this is a test"),
         "this is a {4 more characters}");


    // Test a value that has characters with special treatment.
    assertNotNull(syntax.valueToSanitizedString("#\"\r\n\t"));
    assertEquals(syntax.valueToSanitizedString("#\"\r\n\t"), "#23'\\r\\n\\t");


    // Test a value that has a non-ASCII character whose UTF-8 representation
    // requires two bytes.  That character should be preserved.
    assertNotNull(syntax.valueToSanitizedString("jalape\u00f1o"));
    assertEquals(syntax.valueToSanitizedString("jalape\u00f1o"),
         "jalape\u00f1o");


    // Test a value that has a non-ASCII character whose UTF-8 representation
    // requires four bytes.  That character should be preserved.
    assertNotNull(syntax.valueToSanitizedString("Smile \ud83d\ude00"));
    assertEquals(syntax.valueToSanitizedString("Smile \ud83d\ude00"),
         "Smile \ud83d\ude00");


    // Test a value that has a non-ASCII character whose UTF-8 representation
    // requires eight bytes.  That character should be preserved.
    assertNotNull(syntax.valueToSanitizedString(
         "Flag \ud83c\uddfa\ud83c\uddf8"));
    assertEquals(syntax.valueToSanitizedString("Flag \ud83c\uddfa\ud83c\uddf8"),
         "Flag \ud83c\uddfa\ud83c\uddf8");


    // Test a value with an ASCII null character, which should be encoded.
    assertNotNull(syntax.valueToSanitizedString("Null \u0000"));
    assertEquals(syntax.valueToSanitizedString("Null \u0000"), "Null #00");


    // Test a value with an ASCII delete character, which should be encoded.
    assertNotNull(syntax.valueToSanitizedString("Null \u007f"));
    assertEquals(syntax.valueToSanitizedString("Null \u007f"), "Null #7f");


    // Test a value with a Unicode padding character, which requires two bytes
    // to represent in UTF-8, and should be encoded.
    assertNotNull(syntax.valueToSanitizedString("Pad \u0080"));
    assertEquals(syntax.valueToSanitizedString("Null \u0080"), "Null #c2#80");
  }



  /**
   * Provides test coverage for the sanitize method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSanitize()
         throws Exception
  {
    final StringLogFieldSyntax syntax = new StringLogFieldSyntax(10);


    // Test a value that doesn't require any sanitization.
    assertNotNull(syntax.sanitize("test"));
    assertEquals(syntax.sanitize("test"), "test");


    // Test a value that is more than one character longer than the maximum
    // length.
    assertNotNull(syntax.sanitize("it's a test"));
    assertEquals(syntax.sanitize("it's a test"),
         "it's a tes{1 more character}");


    // Test a value that is more than one character longer than the maximum
    // length.
    assertNotNull(syntax.sanitize("this is a test"));
    assertEquals(syntax.sanitize("this is a test"),
         "this is a {4 more characters}");


    // Test a value that has characters with special treatment.
    assertNotNull(syntax.sanitize("#\"\r\n\t"));
    assertEquals(syntax.sanitize("#\"\r\n\t"), "#23'\\r\\n\\t");


    // Test a value that has a non-ASCII character whose UTF-8 representation
    // requires two bytes.  That character should be preserved.
    assertNotNull(syntax.sanitize("jalape\u00f1o"));
    assertEquals(syntax.sanitize("jalape\u00f1o"), "jalape\u00f1o");


    // Test a value that has a non-ASCII character whose UTF-8 representation
    // requires four bytes.  That character should be preserved.
    assertNotNull(syntax.sanitize("Smile \ud83d\ude00"));
    assertEquals(syntax.sanitize("Smile \ud83d\ude00"), "Smile \ud83d\ude00");


    // Test a value that has a non-ASCII character whose UTF-8 representation
    // requires eight bytes.  That character should be preserved.
    assertNotNull(syntax.sanitize(
         "Flag \ud83c\uddfa\ud83c\uddf8"));
    assertEquals(syntax.sanitize("Flag \ud83c\uddfa\ud83c\uddf8"),
         "Flag \ud83c\uddfa\ud83c\uddf8");


    // Test a value with an ASCII null character, which should be encoded.
    assertNotNull(syntax.sanitize("Null \u0000"));
    assertEquals(syntax.sanitize("Null \u0000"), "Null #00");


    // Test a value with an ASCII delete character, which should be encoded.
    assertNotNull(syntax.sanitize("Null \u007f"));
    assertEquals(syntax.sanitize("Null \u007f"), "Null #7f");


    // Test a value with a Unicode padding character, which requires two bytes
    // to represent in UTF-8, and should be encoded.
    assertNotNull(syntax.sanitize("Pad \u0080"));
    assertEquals(syntax.sanitize("Null \u0080"), "Null #c2#80");
  }



  /**
   * Provides test coverage for the redact methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedact()
         throws Exception
  {
    final StringLogFieldSyntax syntax = new StringLogFieldSyntax(100);


    // Test redacting a complete value.
    final String redacted1 = syntax.redactEntireValue();
    assertNotNull(redacted1);
    assertEquals(redacted1, "{REDACTED}");


    // Test redacting value components, which in this case will be the same as
    // redacting a complete value.
    final String redacted2 = syntax.redactComponents("test");
    assertNotNull(redacted2);
    assertEquals(redacted2, "{REDACTED}");


    // Verify that the syntax properly identifies that the redacted output is
    // redacted.
    assertTrue(syntax.valueStringIsCompletelyRedacted(redacted1));
    assertTrue(syntax.valueStringIsCompletelyRedacted(redacted2));

    assertTrue(syntax.valueStringIncludesRedactedComponent(redacted1));
    assertTrue(syntax.valueStringIncludesRedactedComponent(redacted2));


    // Verify that the syntax properly identifies that the redacted output is
    // not tokenized.
    assertFalse(syntax.valueStringIsCompletelyTokenized(redacted1));
    assertFalse(syntax.valueStringIsCompletelyTokenized(redacted2));

    assertFalse(syntax.valueStringIncludesTokenizedComponent(redacted1));
    assertFalse(syntax.valueStringIncludesTokenizedComponent(redacted2));
  }



  /**
   * Provides test coverage for the tokenize methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTokenize()
         throws Exception
  {
    final StringLogFieldSyntax syntax = new StringLogFieldSyntax(100);


    // Tokenize a value with the test pepper.
    final byte[] pepper1 = StaticUtils.randomBytes(10, false);
    final String tokenized1 = syntax.tokenizeEntireValue("test", pepper1);
    assertNotNull(tokenized1);
    assertTrue(tokenized1.startsWith("{TOKENIZED:"));
    assertTrue(tokenized1.endsWith("}"));
    assertEquals(tokenized1.length(), 28);

    assertEquals(syntax.tokenizeComponents("test", pepper1), tokenized1);
    assertEquals(syntax.tokenize("test", pepper1), tokenized1);


    // Tokenize the same value with the same pepper and verify that we get the
    // same result.
    final String tokenized2 = syntax.tokenizeEntireValue("test", pepper1);
    assertNotNull(tokenized2);
    assertEquals(tokenized2, tokenized1);


    // Tokenize the same value with a different pepper and verify that we get a
    // different result.
    final byte[] pepper2 = StaticUtils.randomBytes(10, false);
    final String tokenized3 = syntax.tokenizeEntireValue("test", pepper2);
    assertNotNull(tokenized3);
    assertTrue(tokenized3.startsWith("{TOKENIZED:"));
    assertTrue(tokenized3.endsWith("}"));
    assertEquals(tokenized3.length(), 28);
    assertFalse(tokenized3.equals(tokenized1));

    assertEquals(syntax.tokenizeComponents("test", pepper2), tokenized3);
    assertEquals(syntax.tokenize("test", pepper2), tokenized3);


    // Tokenize a different value with the original pepper and verify that we
    // get a different result.
    final String tokenized4 = syntax.tokenizeEntireValue("different", pepper1);
    assertNotNull(tokenized4);
    assertTrue(tokenized4.startsWith("{TOKENIZED:"));
    assertTrue(tokenized4.endsWith("}"));
    assertEquals(tokenized4.length(), 28);
    assertFalse(tokenized4.equals(tokenized1));
    assertFalse(tokenized4.equals(tokenized3));

    assertEquals(syntax.tokenizeComponents("different", pepper1), tokenized4);
    assertEquals(syntax.tokenize("different", pepper1), tokenized4);


    // Verify that the syntax properly identifies that tokenized output is
    // tokenized.
    assertTrue(syntax.valueStringIsCompletelyTokenized(tokenized1));
    assertTrue(syntax.valueStringIsCompletelyTokenized(tokenized2));
    assertTrue(syntax.valueStringIsCompletelyTokenized(tokenized3));
    assertTrue(syntax.valueStringIsCompletelyTokenized(tokenized4));

    assertTrue(syntax.valueStringIncludesTokenizedComponent(tokenized1));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(tokenized2));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(tokenized3));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(tokenized4));


    // Verify that the syntax properly identifies that tokenized output is not
    // redacted.
    assertFalse(syntax.valueStringIsCompletelyRedacted(tokenized1));
    assertFalse(syntax.valueStringIsCompletelyRedacted(tokenized2));
    assertFalse(syntax.valueStringIsCompletelyRedacted(tokenized3));
    assertFalse(syntax.valueStringIsCompletelyRedacted(tokenized4));

    assertFalse(syntax.valueStringIncludesRedactedComponent(tokenized1));
    assertFalse(syntax.valueStringIncludesRedactedComponent(tokenized2));
    assertFalse(syntax.valueStringIncludesRedactedComponent(tokenized3));
    assertFalse(syntax.valueStringIncludesRedactedComponent(tokenized4));
  }
}
