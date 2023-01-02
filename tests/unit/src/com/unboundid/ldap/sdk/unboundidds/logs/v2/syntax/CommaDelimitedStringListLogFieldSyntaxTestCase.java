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



import java.util.Arrays;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONBuffer;



/**
 * This class provides a set of test cases for the string log field syntax.
 */
public final class CommaDelimitedStringListLogFieldSyntaxTestCase
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
    final CommaDelimitedStringListLogFieldSyntax syntax =
         new CommaDelimitedStringListLogFieldSyntax(100);

    assertEquals(syntax.getMaxStringLengthCharacters(), 100);

    assertNotNull(syntax.getSyntaxName());
    assertEquals(syntax.getSyntaxName(), "comma-delimited-string-list");

    assertNotNull(
         syntax.valueToSanitizedString(Collections.<String>emptyList()));
    assertEquals(
         syntax.valueToSanitizedString(Collections.<String>emptyList()),
         "");

    assertNotNull(
         syntax.valueToSanitizedString(Collections.singletonList("test")));
    assertEquals(
         syntax.valueToSanitizedString(Collections.singletonList("test")),
         "test");

    assertNotNull(
         syntax.valueToSanitizedString(Arrays.asList("test1", "test2")));
    assertEquals(
         syntax.valueToSanitizedString(Arrays.asList("test1", "test2")),
         "test1,test2");

    assertNotNull(
         syntax.valueToSanitizedString(Arrays.asList("test1", "test2",
              "test3")));
    assertEquals(
         syntax.valueToSanitizedString(Arrays.asList("test1", "test2",
              "test3")),
         "test1,test2,test3");

    assertNotNull(syntax.parseValue(""));
    assertEquals(syntax.parseValue(""), Collections.<String>emptyList());

    assertNotNull(syntax.parseValue("test"));
    assertEquals(syntax.parseValue("test"), Collections.singletonList("test"));

    assertNotNull(syntax.parseValue("test1,test2"));
    assertEquals(syntax.parseValue("test1,test2"),
         Arrays.asList("test1", "test2"));

    assertNotNull(syntax.parseValue("test1 , test2 , test3"));
    assertEquals(syntax.parseValue("test1 , test2 , test3"),
         Arrays.asList("test1", "test2", "test3"));

    assertNotNull(syntax.parseValue(","));
    assertEquals(syntax.parseValue(","), Arrays.asList("", ""));

    assertNotNull(syntax.parseValue("test,"));
    assertEquals(syntax.parseValue("test,"), Arrays.asList("test", ""));

    assertNotNull(syntax.parseValue(",test"));
    assertEquals(syntax.parseValue(",test"), Arrays.asList("", "test"));

    assertNotNull(syntax.parseValue("test1,,test"));
    assertEquals(syntax.parseValue("test1,,test2"),
         Arrays.asList("test1", "", "test2"));

    assertFalse(syntax.valueStringIsCompletelyRedacted("test"));
    assertTrue(syntax.valueStringIsCompletelyRedacted("{REDACTED}"));

    assertTrue(syntax.completelyRedactedValueConformsToSyntax());

    assertNotNull(syntax.redactEntireValue());
    assertEquals(syntax.redactEntireValue(), "{REDACTED}");

    assertTrue(syntax.supportsRedactedComponents());

    assertFalse(syntax.valueStringIncludesRedactedComponent("test"));
    assertTrue(syntax.valueStringIncludesRedactedComponent("{REDACTED}"));
    assertTrue(syntax.valueStringIncludesRedactedComponent(
         "{REDACTED},{REDACTED}"));

    assertTrue(syntax.valueWithRedactedComponentsConformsToSyntax());

    assertNotNull(syntax.redactComponents(Collections.<String>emptyList()));
    assertEquals(syntax.redactComponents(Collections.<String>emptyList()), "");

    assertNotNull(
         syntax.redactComponents(Collections.singletonList("test")));
    assertEquals(
         syntax.redactComponents(Collections.singletonList("test")),
         "{REDACTED}");

    assertNotNull(
         syntax.redactComponents(Arrays.asList("test1", "test2")));
    assertEquals(
         syntax.redactComponents(Arrays.asList("test1", "test2")),
         "{REDACTED},{REDACTED}");

    assertNotNull(
         syntax.redactComponents(Arrays.asList("test1", "test2", "test3")));
    assertEquals(
         syntax.redactComponents(Arrays.asList("test1", "test2", "test3")),
         "{REDACTED},{REDACTED},{REDACTED}");

    assertFalse(syntax.valueStringIsCompletelyTokenized("test"));
    assertTrue(syntax.valueStringIsCompletelyTokenized("{TOKENIZED:abcdef}"));

    assertTrue(syntax.completelyTokenizedValueConformsToSyntax());

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    assertNotNull(
         syntax.tokenizeEntireValue(Collections.<String>emptyList(), pepper));
    assertTrue(syntax.tokenizeEntireValue(Collections.<String>emptyList(),
         pepper).startsWith("{TOKENIZED:"));
    assertTrue(syntax.tokenizeEntireValue(Collections.<String>emptyList(),
         pepper).endsWith("}"));
    assertFalse(syntax.tokenizeEntireValue(Collections.<String>emptyList(),
         pepper).contains(","));

    assertNotNull(
         syntax.tokenizeEntireValue(Collections.singletonList("test"), pepper));
    assertTrue(syntax.tokenizeEntireValue(Collections.singletonList("test"),
         pepper).startsWith("{TOKENIZED:"));
    assertTrue(syntax.tokenizeEntireValue(Collections.singletonList("test"),
         pepper).endsWith("}"));
    assertFalse(syntax.tokenizeEntireValue(Collections.singletonList("test"),
         pepper).contains(","));

    assertNotNull(
         syntax.tokenizeEntireValue(Arrays.asList("test1", "test2"), pepper));
    assertTrue(syntax.tokenizeEntireValue(Arrays.asList("test1", "test2"),
         pepper).startsWith("{TOKENIZED:"));
    assertTrue(syntax.tokenizeEntireValue(Arrays.asList("test1", "test2"),
         pepper).endsWith("}"));
    assertFalse(syntax.tokenizeEntireValue(Arrays.asList("test1", "test2"),
         pepper).contains(","));

    assertTrue(syntax.supportsTokenizedComponents());

    assertFalse(syntax.valueStringIncludesTokenizedComponent("test"));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(
         "{TOKENIZED:abcdef}"));
    assertTrue(syntax.valueStringIncludesTokenizedComponent(
         "{TOKENIZED:abcdef},{TOKENIZED:123456}"));

    assertTrue(syntax.valueWithTokenizedComponentsConformsToSyntax());

    final String emptyListTokenizedComponents =
         syntax.tokenizeComponents(Collections.<String>emptyList(), pepper);
    assertNotNull(emptyListTokenizedComponents);
    assertEquals(emptyListTokenizedComponents, "");

    final String singleItemListTokenizedComponents =
         syntax.tokenizeComponents(Collections.singletonList("test"), pepper);
    assertNotNull(singleItemListTokenizedComponents);
    assertTrue(singleItemListTokenizedComponents.startsWith("{TOKENIZED:"));
    assertTrue(singleItemListTokenizedComponents.indexOf("{TOKENIZED:", 1) < 0);
    assertEquals(singleItemListTokenizedComponents.indexOf("}"),
         (singleItemListTokenizedComponents.length() - 1));

    final String multiItemListTokenizedComponents =
         syntax.tokenizeComponents(Arrays.asList("test1", "test2"), pepper);
    assertNotNull(multiItemListTokenizedComponents);
    assertTrue(multiItemListTokenizedComponents.startsWith("{TOKENIZED:"));
    assertTrue(multiItemListTokenizedComponents.indexOf("{TOKENIZED:", 1) > 0);
    assertTrue(multiItemListTokenizedComponents.endsWith("}"));
    assertTrue(multiItemListTokenizedComponents.indexOf("}") <
         (multiItemListTokenizedComponents.length() - 1));
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
    final CommaDelimitedStringListLogFieldSyntax syntax =
         new CommaDelimitedStringListLogFieldSyntax(10);

    final ByteStringBuffer buffer = new ByteStringBuffer();
    syntax.logSanitizedFieldToTextFormattedLog("abc",
         Arrays.asList("short", "LongEnoughToTruncate"),
         buffer);
    assertEquals(buffer.toString(),
         " abc=\"short,LongEnough{10 more characters}\"");

    buffer.clear();
    syntax.logCompletelyRedactedFieldToTextFormattedLog("def", buffer);
    assertEquals(buffer.toString(), " def=\"{REDACTED}\"");

    buffer.clear();
    syntax.logRedactedComponentsFieldToTextFormattedLog("ghi",
         Arrays.asList("short", "LongEnoughToTruncate"),
         buffer);
    assertEquals(buffer.toString(), " ghi=\"{REDACTED},{REDACTED}\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToTextFormattedLog("jkl",
         Arrays.asList("short", "LongEnoughToTruncate"),
         pepper, buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(" jkl=\"{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\""));

    buffer.clear();
    syntax.logTokenizedComponentsFieldToTextFormattedLog("mno",
         Arrays.asList("short", "LongEnoughToTruncate"),
         pepper, buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(" mno=\"{TOKENIZED:"));
    assertTrue(tokenizedComponentsString.contains("},{TOKENIZED:"));
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
    final CommaDelimitedStringListLogFieldSyntax syntax =
         new CommaDelimitedStringListLogFieldSyntax(10);

    final JSONBuffer buffer = new JSONBuffer();
    buffer.beginObject();
    syntax.logSanitizedFieldToJSONFormattedLog("abc",
         Arrays.asList("short", "LongEnoughToTruncate"),
         buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"abc\":\"short,LongEnough{10 more characters}\" }");

    buffer.clear();
    buffer.beginObject();
    syntax.logCompletelyRedactedFieldToJSONFormattedLog("def", buffer);
    buffer.endObject();
    assertEquals(buffer.toString(), "{ \"def\":\"{REDACTED}\" }");

    buffer.clear();
    buffer.beginObject();
    syntax.logRedactedComponentsFieldToJSONFormattedLog("ghi",
         Arrays.asList("short", "LongEnoughToTruncate"),
         buffer);
    buffer.endObject();
    assertEquals(buffer.toString(), "{ \"ghi\":\"{REDACTED},{REDACTED}\" }");

    buffer.clear();
    buffer.beginObject();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToJSONFormattedLog("jkl",
         Arrays.asList("short", "LongEnoughToTruncate"),
         pepper, buffer);
    buffer.endObject();
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith("{ \"jkl\":\"{TOKENIZED:"));
    assertFalse(completelyTokenizedString.contains("},{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\" }"));

    buffer.clear();
    buffer.beginObject();
    syntax.logTokenizedComponentsFieldToJSONFormattedLog("mno",
         Arrays.asList("short", "LongEnoughToTruncate"),
         pepper, buffer);
    buffer.endObject();
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith("{ \"mno\":\"{TOKENIZED:"));
    assertTrue(tokenizedComponentsString.contains("},{TOKENIZED:"));
    assertTrue(tokenizedComponentsString.endsWith("}\" }"));
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
    final CommaDelimitedStringListLogFieldSyntax syntax =
         new CommaDelimitedStringListLogFieldSyntax(10);

    final JSONBuffer buffer = new JSONBuffer();
    syntax.logSanitizedValueToJSONFormattedLog(
         Arrays.asList("short", "LongEnoughToTruncate"),
         buffer);
    assertEquals(buffer.toString(),
         "\"short,LongEnough{10 more characters}\"");

    buffer.clear();
    syntax.logCompletelyRedactedValueToJSONFormattedLog(buffer);
    assertEquals(buffer.toString(), "\"{REDACTED}\"");

    buffer.clear();
    syntax.logRedactedComponentsValueToJSONFormattedLog(
         Arrays.asList("short", "LongEnoughToTruncate"),
         buffer);
    assertEquals(buffer.toString(), "\"{REDACTED},{REDACTED}\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedValueToJSONFormattedLog(
         Arrays.asList("short", "LongEnoughToTruncate"),
         pepper, buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith("\"{TOKENIZED:"));
    assertFalse(completelyTokenizedString.contains("},{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\""));

    buffer.clear();
    syntax.logTokenizedComponentsValueToJSONFormattedLog(
         Arrays.asList("short", "LongEnoughToTruncate"),
         pepper, buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith("\"{TOKENIZED:"));
    assertTrue(tokenizedComponentsString.contains("},{TOKENIZED:"));
    assertTrue(tokenizedComponentsString.endsWith("}\""));
  }
}
