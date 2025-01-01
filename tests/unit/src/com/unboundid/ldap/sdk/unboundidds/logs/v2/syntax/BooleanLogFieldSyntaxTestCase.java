/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONBuffer;



/**
 * This class provides a set of test cases for the Boolean log field syntax.
 */
public final class BooleanLogFieldSyntaxTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the basic functionality of the syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSyntax()
         throws Exception
  {
    final BooleanLogFieldSyntax syntax = BooleanLogFieldSyntax.getInstance();

    assertNotNull(syntax.getSyntaxName());
    assertEquals(syntax.getSyntaxName(), "boolean");

    assertNotNull(syntax.valueToSanitizedString(true));
    assertEquals(syntax.valueToSanitizedString(true), "true");

    final ByteStringBuffer buffer = new ByteStringBuffer();
    syntax.valueToSanitizedString(false, buffer);
    assertEquals(buffer.toString(), "false");

    assertNotNull(syntax.parseValue("true"));
    assertEquals(syntax.parseValue("true"), Boolean.TRUE);

    assertNotNull(syntax.parseValue("false"));
    assertEquals(syntax.parseValue("false"), Boolean.FALSE);

    try
    {
      syntax.parseValue("{REDACTED}");
      fail("Expected an exception when trying to parse a redacted value.");
    }
    catch (final RedactedValueException e)
    {
      // This was expected.
    }

    try
    {
      syntax.parseValue("{TOKENIZED:1234567890ABCDEF}");
      fail("Expected an exception when trying to parse a tokenized value.");
    }
    catch (final TokenizedValueException e)
    {
      // This was expected
    }

    try
    {
      syntax.parseValue("malformed");
      fail("Expected an exception when trying to parse a malformed value.");
    }
    catch (final LogSyntaxException e)
    {
      // This was expected.
      assertFalse((e instanceof RedactedValueException) ||
           (e instanceof TokenizedValueException));
    }

    assertFalse(syntax.completelyRedactedValueConformsToSyntax());

    assertNotNull(syntax.redactEntireValue());
    assertEquals(syntax.redactEntireValue(), "{REDACTED}");

    assertFalse(syntax.supportsRedactedComponents());

    assertFalse(syntax.valueStringIncludesRedactedComponent("true"));
    assertTrue(syntax.valueStringIncludesRedactedComponent("{REDACTED}"));
    assertTrue(syntax.valueStringIncludesRedactedComponent("a{REDACTED}b"));

    assertFalse(syntax.valueWithRedactedComponentsConformsToSyntax());

    assertNotNull(syntax.redactComponents(true));
    assertEquals(syntax.redactComponents(true), "{REDACTED}");

    assertNotNull(syntax.redactComponents(false));
    assertEquals(syntax.redactComponents(false), "{REDACTED}");

    assertFalse(syntax.valueStringIsCompletelyTokenized("true"));
    assertFalse(syntax.valueStringIsCompletelyTokenized("false"));

    assertFalse(syntax.completelyTokenizedValueConformsToSyntax());

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    assertNotNull(syntax.tokenizeEntireValue(true, pepper));
    assertTrue(syntax.tokenizeEntireValue(true, pepper).startsWith(
         "{TOKENIZED:"));
    assertTrue(syntax.tokenizeEntireValue(true, pepper).endsWith("}"));

    assertFalse(syntax.supportsTokenizedComponents());

    assertFalse(syntax.valueStringIncludesTokenizedComponent("test"));

    assertFalse(syntax.valueWithTokenizedComponentsConformsToSyntax());

    assertNotNull(syntax.tokenizeComponents(true, pepper));
    assertTrue(syntax.tokenizeComponents(true, pepper).
         startsWith("{TOKENIZED:"));
    assertTrue(syntax.tokenizeComponents(true, pepper).endsWith("}"));
  }



  /**
   * Tests  the methods that may be used for logging text-formatted messages.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTextLogMethods()
         throws Exception
  {
    final BooleanLogFieldSyntax syntax = BooleanLogFieldSyntax.getInstance();

    final ByteStringBuffer buffer = new ByteStringBuffer();
    syntax.logSanitizedFieldToTextFormattedLog("abc", true, buffer);
    assertEquals(buffer.toString(), " abc=true");

    buffer.clear();
    syntax.logSanitizedFieldToTextFormattedLog("def", false, buffer);
    assertEquals(buffer.toString(), " def=false");

    buffer.clear();
    syntax.logCompletelyRedactedFieldToTextFormattedLog("ghi", buffer);
    assertEquals(buffer.toString(), " ghi=\"{REDACTED}\"");

    buffer.clear();
    syntax.logRedactedComponentsFieldToTextFormattedLog("jkl", true, buffer);
    assertEquals(buffer.toString(), " jkl=\"{REDACTED}\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToTextFormattedLog("mno", true, pepper,
         buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(" mno=\"{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\""));

    buffer.clear();
    syntax.logTokenizedComponentsFieldToTextFormattedLog("pqr", true, pepper,
         buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(" pqr=\"{TOKENIZED:"));
    assertEquals(tokenizedComponentsString,
         " pqr=" + completelyTokenizedString.substring(5));
  }



  /**
   * Tests the methods that may be used for logging JSON-formatted messages.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJSONLogMethods()
         throws Exception
  {
    final BooleanLogFieldSyntax syntax = BooleanLogFieldSyntax.getInstance();

    final JSONBuffer buffer = new JSONBuffer();
    buffer.beginObject();
    syntax.logSanitizedFieldToJSONFormattedLog("abc", true, buffer);
    buffer.endObject();
    assertEquals(buffer.toString(), "{ \"abc\":true }");

    buffer.clear();
    buffer.beginObject();
    syntax.logSanitizedFieldToJSONFormattedLog("def", false, buffer);
    buffer.endObject();
    assertEquals(buffer.toString(), "{ \"def\":false }");

    buffer.clear();
    buffer.beginObject();
    syntax.logCompletelyRedactedFieldToJSONFormattedLog("ghi", buffer);
    buffer.endObject();
    assertEquals(buffer.toString(), "{ \"ghi\":\"{REDACTED}\" }");

    buffer.clear();
    buffer.beginObject();
    syntax.logRedactedComponentsFieldToJSONFormattedLog("jkl", true, buffer);
    buffer.endObject();
    assertEquals(buffer.toString(), "{ \"jkl\":\"{REDACTED}\" }");

    buffer.clear();
    buffer.beginObject();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToJSONFormattedLog("mno", false, pepper,
         buffer);
    buffer.endObject();
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith("{ \"mno\":\"{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\" }"));

    buffer.clear();
    buffer.beginObject();
    syntax.logTokenizedComponentsFieldToJSONFormattedLog("pqr", false, pepper,
         buffer);
    buffer.endObject();
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith("{ \"pqr\":\"{TOKENIZED:"));
    assertEquals(tokenizedComponentsString,
         "{ \"pqr\":" + completelyTokenizedString.substring(8));
  }



  /**
   * Tests the methods that may be used for logging JSON-formatted values
   * (without field names).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJSONValueLogMethods()
         throws Exception
  {
    final BooleanLogFieldSyntax syntax = BooleanLogFieldSyntax.getInstance();

    final JSONBuffer buffer = new JSONBuffer();
    syntax.logSanitizedValueToJSONFormattedLog(true, buffer);
    assertEquals(buffer.toString(), "true");

    buffer.clear();
    syntax.logSanitizedValueToJSONFormattedLog(false, buffer);
    assertEquals(buffer.toString(), "false");

    buffer.clear();
    syntax.logCompletelyRedactedValueToJSONFormattedLog(buffer);
    assertEquals(buffer.toString(), "\"{REDACTED}\"");

    buffer.clear();
    syntax.logRedactedComponentsValueToJSONFormattedLog(true, buffer);
    assertEquals(buffer.toString(), "\"{REDACTED}\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedValueToJSONFormattedLog(false, pepper, buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith("\"{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\""));

    buffer.clear();
    syntax.logTokenizedComponentsValueToJSONFormattedLog(false, pepper, buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith("\"{TOKENIZED:"));
    assertEquals(tokenizedComponentsString, completelyTokenizedString);
  }
}
