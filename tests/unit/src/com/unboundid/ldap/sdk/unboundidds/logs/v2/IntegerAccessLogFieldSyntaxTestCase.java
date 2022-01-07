/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the integer access log field
 * syntax.
 */
public final class IntegerAccessLogFieldSyntaxTestCase
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
    final IntegerAccessLogFieldSyntax syntax =
         IntegerAccessLogFieldSyntax.getInstance();

    assertNotNull(syntax.getSyntaxName());
    assertEquals(syntax.getSyntaxName(), "integer");

    assertNotNull(syntax.valueToSanitizedString(0L));
    assertEquals(syntax.valueToSanitizedString(0L), "0");

    final ByteStringBuffer buffer = new ByteStringBuffer();
    syntax.valueToSanitizedString(12345L, buffer);
    assertEquals(buffer.toString(), "12345");

    buffer.clear();
    syntax.valueToSanitizedString(234, buffer);
    assertEquals(buffer.toString(), "234");

    assertNotNull(syntax.parseValue("54321"));
    assertEquals(syntax.parseValue("54321"), Long.valueOf(54321L));

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

    assertTrue(syntax.valueStringIsCompletelyRedacted("{REDACTED}"));
    assertTrue(syntax.valueStringIsCompletelyRedacted("-999999999999999999"));
    assertFalse(syntax.valueStringIsCompletelyRedacted("12345"));
    assertFalse(syntax.valueStringIsCompletelyRedacted("malformed"));

    assertTrue(syntax.completelyRedactedValueConformsToSyntax());

    assertNotNull(syntax.redactEntireValue());
    assertEquals(syntax.redactEntireValue(), "-999999999999999999");

    assertFalse(syntax.supportsRedactedComponents());

    assertTrue(syntax.valueStringIncludesRedactedComponent("{REDACTED}"));
    assertTrue(syntax.valueStringIncludesRedactedComponent(
         "-999999999999999999"));
    assertFalse(syntax.valueStringIncludesRedactedComponent("12345"));

    assertTrue(syntax.valueWithRedactedComponentsConformsToSyntax());

    assertNotNull(syntax.redactComponents(12345L));
    assertEquals(syntax.redactComponents(12345L), "-999999999999999999");

    assertFalse(syntax.valueStringIsCompletelyTokenized("12345"));
    assertFalse(syntax.valueStringIsCompletelyTokenized("-999999999999999999"));
    assertTrue(syntax.valueStringIsCompletelyTokenized("-999999999123456789"));
    assertTrue(syntax.valueStringIsCompletelyTokenized("{TOKENIZED:abcdef}"));

    assertTrue(syntax.completelyTokenizedValueConformsToSyntax());

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    assertNotNull(syntax.tokenizeEntireValue(12345L, pepper));
    assertTrue(syntax.tokenizeEntireValue(12345L, pepper).startsWith(
         "-999999999"));
    assertFalse(syntax.tokenizeEntireValue(12345L, pepper).equals(
         "-999999999999999999"));
    Long.parseLong(syntax.tokenizeEntireValue(12345L, pepper));
    assertEquals(syntax.tokenizeEntireValue(12345L, pepper),
         syntax.tokenizeEntireValue(12345L, pepper));

    assertFalse(syntax.supportsTokenizedComponents());

    assertFalse(syntax.valueStringIncludesTokenizedComponent("test"));
    assertFalse(syntax.valueStringIncludesTokenizedComponent("12345"));
    assertFalse(syntax.valueStringIncludesTokenizedComponent(
         "-999999999999999999"));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(
         "-999999999123456789"));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(
         "{TOKENIZED:abcdef}"));

    assertTrue(syntax.valueWithTokenizedComponentsConformsToSyntax());

    assertNotNull(syntax.tokenizeComponents(12345L, pepper));
    assertTrue(syntax.tokenizeComponents(12345L, pepper).
         startsWith("-999999999"));
    assertFalse(syntax.tokenizeComponents(12345L, pepper).equals(
         "-999999999999999999"));
  }
}
