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



import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the generalized time log field
 * syntax.
 */
public final class GeneralizedTimeLogFieldSyntaxTestCase
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
    final GeneralizedTimeLogFieldSyntax syntax =
         GeneralizedTimeLogFieldSyntax.getInstance();

    assertNotNull(syntax.getSyntaxName());
    assertEquals(syntax.getSyntaxName(), "generalized-time");

    final Date now = new Date();
    final String nowString = syntax.valueToSanitizedString(now);
    assertNotNull(nowString);
    assertEquals(StaticUtils.decodeGeneralizedTime(nowString), now);

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
    assertTrue(syntax.valueStringIsCompletelyRedacted("99990101000000.000Z"));

    assertNotNull(syntax.redactEntireValue());
    assertEquals(syntax.redactEntireValue(), "99990101000000.000Z");

    assertTrue(syntax.completelyRedactedValueConformsToSyntax());

    assertFalse(syntax.supportsRedactedComponents());

    assertFalse(syntax.valueStringIncludesRedactedComponent(nowString));
    assertTrue(syntax.valueStringIncludesRedactedComponent("{REDACTED}"));
    assertTrue(syntax.valueStringIncludesRedactedComponent(
         "99990101000000.000Z"));

    assertTrue(syntax.valueWithRedactedComponentsConformsToSyntax());

    assertFalse(syntax.valueStringIsCompletelyTokenized(nowString));
    assertTrue(syntax.valueStringIsCompletelyTokenized("{TOKENIZED:abcdef}"));
    assertTrue(syntax.valueStringIsCompletelyTokenized("88880102123456.789Z"));

    assertTrue(syntax.completelyTokenizedValueConformsToSyntax());

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    final String tokenizedNow = syntax.tokenizeEntireValue(now, pepper);
    assertNotNull(tokenizedNow);
    assertTrue(tokenizedNow.startsWith("8888"));
    assertTrue(syntax.valueStringIsCompletelyTokenized(tokenizedNow));

    assertFalse(syntax.supportsTokenizedComponents());
    assertFalse(syntax.valueStringIncludesTokenizedComponent(nowString));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(
         "{TOKENIZED:abcdef}"));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(
         "88880102123456.789Z"));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(tokenizedNow));

    assertTrue(syntax.valueWithTokenizedComponentsConformsToSyntax());
  }
}
