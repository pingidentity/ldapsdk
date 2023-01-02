/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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
 * This class provides a set of test cases for the string access log field
 * syntax.
 */
public final class StringLogFieldSyntaxTestCase
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
    final StringLogFieldSyntax syntax =
         new StringLogFieldSyntax(100);

    assertEquals(syntax.getMaxStringLengthCharacters(), 100);

    assertNotNull(syntax.getSyntaxName());
    assertEquals(syntax.getSyntaxName(), "string");

    assertNotNull(syntax.valueToSanitizedString("test"));
    assertEquals(syntax.valueToSanitizedString("test"), "test");

    assertNotNull(syntax.parseValue("test"));
    assertEquals(syntax.parseValue("test"), "test");

    assertFalse(syntax.valueStringIsCompletelyRedacted("test"));

    assertTrue(syntax.completelyRedactedValueConformsToSyntax());

    assertNotNull(syntax.redactEntireValue());
    assertEquals(syntax.redactEntireValue(), "{REDACTED}");

    assertFalse(syntax.supportsRedactedComponents());

    assertFalse(syntax.valueStringIncludesRedactedComponent("test"));
    assertTrue(syntax.valueStringIncludesRedactedComponent("{REDACTED}"));
    assertTrue(syntax.valueStringIncludesRedactedComponent("a{REDACTED}b"));

    assertTrue(syntax.valueWithRedactedComponentsConformsToSyntax());

    assertNotNull(syntax.redactComponents("test"));
    assertEquals(syntax.redactComponents("test"), "{REDACTED}");

    assertFalse(syntax.valueStringIsCompletelyTokenized("test"));

    assertTrue(syntax.completelyTokenizedValueConformsToSyntax());

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    assertNotNull(syntax.tokenizeEntireValue("test", pepper));
    assertTrue(syntax.tokenizeEntireValue("test", pepper).startsWith(
         "{TOKENIZED:"));
    assertTrue(syntax.tokenizeEntireValue("test", pepper).endsWith("}"));

    assertFalse(syntax.supportsTokenizedComponents());

    assertFalse(syntax.valueStringIncludesTokenizedComponent("test"));

    assertTrue(syntax.valueWithTokenizedComponentsConformsToSyntax());

    assertNotNull(syntax.tokenizeComponents("test", pepper));
    assertTrue(syntax.tokenizeComponents("test", pepper).startsWith(
         "{TOKENIZED:"));
    assertTrue(syntax.tokenizeComponents("test", pepper).endsWith("}"));
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
    final StringLogFieldSyntax syntax = new StringLogFieldSyntax(10);

    final ByteStringBuffer buffer = new ByteStringBuffer();
    syntax.logSanitizedFieldToTextFormattedLog("abc", "foo", buffer);
    assertEquals(buffer.toString(), " abc=\"foo\"");

    buffer.clear();
    syntax.logSanitizedFieldToTextFormattedLog("def", "ThisIsALongerValue",
         buffer);
    assertEquals(buffer.toString(), " def=\"ThisIsALon{8 more characters}\"");

    buffer.clear();
    syntax.logCompletelyRedactedFieldToTextFormattedLog("ghi", buffer);
    assertEquals(buffer.toString(), " ghi=\"{REDACTED}\"");

    buffer.clear();
    syntax.logRedactedComponentsFieldToTextFormattedLog("jkl",
         "ThisIsALongerValue", buffer);
    assertEquals(buffer.toString(), " jkl=\"{REDACTED}\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToTextFormattedLog("mno",
         "ThisIsALongerValue", pepper, buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         " mno=\"{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\""));

    buffer.clear();
    syntax.logTokenizedComponentsFieldToTextFormattedLog("pqr",
         "ThisIsALongerValue", pepper, buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(" pqr=\"{TOKENIZED:"));
    assertEquals(tokenizedComponentsString,
         " pqr=\"" + completelyTokenizedString.substring(6));
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
    final StringLogFieldSyntax syntax = new StringLogFieldSyntax(10);

    final JSONBuffer buffer = new JSONBuffer();
    buffer.beginObject();
    syntax.logSanitizedFieldToJSONFormattedLog("abc", "ThisIsALongerValue",
         buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"abc\":\"ThisIsALon{8 more characters}\" }");

    buffer.clear();
    buffer.beginObject();
    syntax.logCompletelyRedactedFieldToJSONFormattedLog("def", buffer);
    buffer.endObject();
    assertEquals(buffer.toString(), "{ \"def\":\"{REDACTED}\" }");

    buffer.clear();
    buffer.beginObject();
    syntax.logRedactedComponentsFieldToJSONFormattedLog("ghi",
         "ThisIsALongerValue", buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"ghi\":\"{REDACTED}\" }");

    buffer.clear();
    buffer.beginObject();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToJSONFormattedLog("jkl",
         "ThisIsALongerValue", pepper, buffer);
    buffer.endObject();
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         "{ \"jkl\":\"{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\" }"));

    buffer.clear();
    buffer.beginObject();
    syntax.logTokenizedComponentsFieldToJSONFormattedLog("mno",
         "ThisIsALongerValue", pepper, buffer);
    buffer.endObject();
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(
         "{ \"mno\":\"{TOKENIZED:"));
    assertEquals(tokenizedComponentsString,
         "{ \"mno\":" + completelyTokenizedString.substring(8));
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
    final StringLogFieldSyntax syntax = new StringLogFieldSyntax(10);

    final JSONBuffer buffer = new JSONBuffer();
    syntax.logSanitizedValueToJSONFormattedLog("ThisIsALongerValue",
         buffer);
    assertEquals(buffer.toString(), "\"ThisIsALon{8 more characters}\"");

    buffer.clear();
    syntax.logCompletelyRedactedValueToJSONFormattedLog(buffer);
    assertEquals(buffer.toString(), "\"{REDACTED}\"");

    buffer.clear();
    syntax.logRedactedComponentsValueToJSONFormattedLog("ThisIsALongerValue",
         buffer);
    assertEquals(buffer.toString(),
         "\"{REDACTED}\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedValueToJSONFormattedLog("ThisIsALongerValue",
         pepper, buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith("\"{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\""));

    buffer.clear();
    syntax.logTokenizedComponentsValueToJSONFormattedLog("ThisIsALongerValue",
         pepper, buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith("\"{TOKENIZED:"));
    assertEquals(tokenizedComponentsString, completelyTokenizedString);
  }
}
