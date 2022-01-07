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
import com.unboundid.util.StaticUtils;



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
}
