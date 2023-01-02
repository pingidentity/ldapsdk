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



import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONBuffer;



/**
 * This class provides a set of test cases for the RFC 3339 timestamp log field
 * syntax.
 */
public final class RFC3339TimestampLogFieldSyntaxTestCase
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
    final RFC3339TimestampLogFieldSyntax syntax =
         RFC3339TimestampLogFieldSyntax.getInstance();

    assertNotNull(syntax.getSyntaxName());
    assertEquals(syntax.getSyntaxName(), "rfc-3339-timestamp");

    final Date now = new Date();
    final String nowString = syntax.valueToSanitizedString(now);
    assertNotNull(nowString);
    assertEquals(StaticUtils.decodeRFC3339Time(nowString), now);

    assertNotNull(syntax.parseValue(nowString));
    assertEquals(syntax.parseValue(nowString), now);

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
      syntax.parseValue("{TOKENIZED:abcdef}");
      fail("Expected an exception when trying to parse a tokenized value.");
    }
    catch (final TokenizedValueException e)
    {
      // This was expected.
    }

    try
    {
      syntax.parseValue("malformed");
      fail("Expected an exception when trying to parse a malformed value.");
    }
    catch (final LogSyntaxException e)
    {
      assertFalse((e instanceof RedactedValueException) ||
           (e instanceof TokenizedValueException));
    }

    assertFalse(syntax.valueStringIsCompletelyRedacted(nowString));
    assertTrue(syntax.valueStringIsCompletelyRedacted("{REDACTED}"));
    assertTrue(syntax.valueStringIsCompletelyRedacted(
         "9999-01-01T00:00:00.000Z"));

    assertNotNull(syntax.redactEntireValue());
    assertEquals(syntax.redactEntireValue(), "9999-01-01T00:00:00.000Z");

    assertTrue(syntax.completelyRedactedValueConformsToSyntax());

    assertFalse(syntax.supportsRedactedComponents());

    assertFalse(syntax.valueStringIncludesRedactedComponent(nowString));
    assertTrue(syntax.valueStringIncludesRedactedComponent("{REDACTED}"));
    assertTrue(syntax.valueStringIncludesRedactedComponent(
         "9999-01-01T00:00:00.000Z"));

    assertTrue(syntax.valueWithRedactedComponentsConformsToSyntax());

    assertFalse(syntax.valueStringIsCompletelyTokenized(nowString));
    assertTrue(syntax.valueStringIsCompletelyTokenized("{TOKENIZED:abcdef}"));
    assertTrue(syntax.valueStringIsCompletelyTokenized(
         "8888-01-02T12:34:56.789Z"));

    assertTrue(syntax.completelyTokenizedValueConformsToSyntax());

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    final String tokenizedNow = syntax.tokenizeEntireValue(now, pepper);
    assertNotNull(tokenizedNow);
    assertTrue(tokenizedNow.startsWith("8888-"));
    assertTrue(syntax.valueStringIsCompletelyTokenized(tokenizedNow));

    assertFalse(syntax.supportsTokenizedComponents());
    assertFalse(syntax.valueStringIncludesTokenizedComponent(nowString));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(
         "{TOKENIZED:abcdef}"));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(
         "8888-01-02T12:34:56.789Z"));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(tokenizedNow));

    assertTrue(syntax.valueWithTokenizedComponentsConformsToSyntax());
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
    final RFC3339TimestampLogFieldSyntax syntax =
         RFC3339TimestampLogFieldSyntax.getInstance();
    final Date now = new Date();

    final ByteStringBuffer buffer = new ByteStringBuffer();
    syntax.logSanitizedFieldToTextFormattedLog("abc", now, buffer);
    assertEquals(buffer.toString(),
         " abc=\"" + StaticUtils.encodeRFC3339Time(now) + "\"");

    buffer.clear();
    syntax.logCompletelyRedactedFieldToTextFormattedLog("def", buffer);
    assertEquals(buffer.toString(), " def=\"9999-01-01T00:00:00.000Z\"");

    buffer.clear();
    syntax.logRedactedComponentsFieldToTextFormattedLog("ghi", now, buffer);
    assertEquals(buffer.toString(), " ghi=\"9999-01-01T00:00:00.000Z\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToTextFormattedLog("jkl", now, pepper,
         buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         " jkl=\"8888-"));
    assertTrue(completelyTokenizedString.endsWith("Z\""));

    buffer.clear();
    syntax.logTokenizedComponentsFieldToTextFormattedLog("mno", now, pepper,
         buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(" mno=\"8888-"));
    assertEquals(tokenizedComponentsString,
         " mno=\"" + completelyTokenizedString.substring(6));
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
    final RFC3339TimestampLogFieldSyntax syntax =
         RFC3339TimestampLogFieldSyntax.getInstance();
    final Date now = new Date();

    final JSONBuffer buffer = new JSONBuffer();
    buffer.beginObject();
    syntax.logSanitizedFieldToJSONFormattedLog("abc", now, buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"abc\":\"" + StaticUtils.encodeRFC3339Time(now) + "\" }");

    buffer.clear();
    buffer.beginObject();
    syntax.logCompletelyRedactedFieldToJSONFormattedLog("def", buffer);
    buffer.endObject();
    assertEquals(buffer.toString(), "{ \"def\":\"9999-01-01T00:00:00.000Z\" }");

    buffer.clear();
    buffer.beginObject();
    syntax.logRedactedComponentsFieldToJSONFormattedLog("ghi", now, buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"ghi\":\"9999-01-01T00:00:00.000Z\" }");

    buffer.clear();
    buffer.beginObject();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToJSONFormattedLog("jkl", now, pepper,
         buffer);
    buffer.endObject();
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         "{ \"jkl\":\"8888-"));
    assertTrue(completelyTokenizedString.endsWith("Z\" }"));

    buffer.clear();
    buffer.beginObject();
    syntax.logTokenizedComponentsFieldToJSONFormattedLog("mno", now, pepper,
         buffer);
    buffer.endObject();
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(
         "{ \"mno\":\"8888-"));
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
    final RFC3339TimestampLogFieldSyntax syntax =
         RFC3339TimestampLogFieldSyntax.getInstance();
    final Date now = new Date();

    final JSONBuffer buffer = new JSONBuffer();
    syntax.logSanitizedValueToJSONFormattedLog(now, buffer);
    assertEquals(buffer.toString(),
         '"' + StaticUtils.encodeRFC3339Time(now) + '"');

    buffer.clear();
    syntax.logCompletelyRedactedValueToJSONFormattedLog(buffer);
    assertEquals(buffer.toString(), "\"9999-01-01T00:00:00.000Z\"");

    buffer.clear();
    syntax.logRedactedComponentsValueToJSONFormattedLog(now, buffer);
    assertEquals(buffer.toString(),
         "\"9999-01-01T00:00:00.000Z\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedValueToJSONFormattedLog(now, pepper, buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith("\"8888-"));
    assertTrue(completelyTokenizedString.endsWith("Z\""));

    buffer.clear();
    syntax.logTokenizedComponentsValueToJSONFormattedLog(now, pepper, buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith("\"8888-"));
    assertEquals(tokenizedComponentsString, completelyTokenizedString);
  }
}
