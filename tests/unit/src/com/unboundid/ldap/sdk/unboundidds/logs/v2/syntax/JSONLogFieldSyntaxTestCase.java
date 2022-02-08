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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax;



import java.util.List;
import java.util.Set;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONBuffer;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;



/**
 * This class provides a set of test cases for the JSON log field syntax.
 */
public final class JSONLogFieldSyntaxTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the basic functionality of the syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicSyntax()
         throws Exception
  {
    final JSONLogFieldSyntax syntax = new JSONLogFieldSyntax(10, null, null);

    assertEquals(syntax.getMaxStringLengthCharacters(), 10);

    assertNotNull(syntax.getIncludedSensitiveFields());
    assertTrue(syntax.getIncludedSensitiveFields().isEmpty());

    assertNotNull(syntax.getExcludedSensitiveFields());
    assertTrue(syntax.getExcludedSensitiveFields().isEmpty());

    assertNotNull(syntax.getSyntaxName());
    assertEquals(syntax.getSyntaxName(), "json");

    assertNotNull(syntax.valueToSanitizedString(JSONObject.EMPTY_OBJECT));
    assertEquals(syntax.valueToSanitizedString(JSONObject.EMPTY_OBJECT),
         "{ }");

    final JSONObject singleFieldObject = new JSONObject(
         new JSONField("foo", "bar"));
    assertNotNull(syntax.valueToSanitizedString(singleFieldObject));
    assertEquals(syntax.valueToSanitizedString(singleFieldObject),
         "{ \"foo\":\"bar\" }");

    final JSONObject multiFieldObject = new JSONObject(
         new JSONField("a", "b"),
         new JSONField("c", "ThisIsALongerValue"),
         new JSONField("d", 123),
         new JSONField("e", 4.5),
         new JSONField("f", true),
         new JSONField("g", JSONNull.NULL),
         new JSONField("h",
              new JSONArray(
                   new JSONString("i"),
                   JSONBoolean.FALSE,
                   new JSONNumber(678),
                   JSONNull.NULL,
                   new JSONObject(new JSONField("j", "k")))),
         new JSONField("l",
              new JSONObject(
                   new JSONField("m", "n"))));
    assertNotNull(syntax.valueToSanitizedString(multiFieldObject));
    assertEquals(syntax.valueToSanitizedString(multiFieldObject),
         "{ \"a\":\"b\", " +
              "\"c\":\"ThisIsALon{8 more characters}\", " +
              "\"d\":123, " +
              "\"e\":4.5, " +
              "\"f\":true, " +
              "\"g\":null, " +
              "\"h\":[ " +
                   "\"i\", " +
                   "false, " +
                   "678, " +
                   "null, " +
                   "{ \"j\":\"k\" } ], " +
              "\"l\":{ \"m\":\"n\" } }");

    assertNotNull(syntax.parseValue(singleFieldObject.toSingleLineString()));
    assertEquals(syntax.parseValue(singleFieldObject.toSingleLineString()),
         singleFieldObject);

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

    assertFalse(syntax.valueStringIsCompletelyRedacted(
         singleFieldObject.toSingleLineString()));
    assertTrue(syntax.valueStringIsCompletelyRedacted(
         "{ \"redacted\":\"{REDACTED}\" }"));
    assertTrue(syntax.valueStringIsCompletelyRedacted(
         "{REDACTED}"));

    assertTrue(syntax.completelyRedactedValueConformsToSyntax());

    assertNotNull(syntax.redactEntireValue());
    assertEquals(syntax.redactEntireValue(),
         "{ \"redacted\":\"{REDACTED}\" }");
    JSONObject tokenizedObject = new JSONObject(syntax.redactEntireValue());

    assertTrue(syntax.supportsRedactedComponents());

    assertTrue(syntax.valueWithRedactedComponentsConformsToSyntax());

    assertNotNull(syntax.redactComponents(singleFieldObject));
    assertEquals(syntax.redactComponents(singleFieldObject),
         "{ \"foo\":\"{REDACTED}\" }");
    tokenizedObject =
         new JSONObject(syntax.redactComponents(singleFieldObject));

    assertNotNull(syntax.redactComponents(multiFieldObject));
    assertEquals(syntax.redactComponents(multiFieldObject),
         "{ \"a\":\"{REDACTED}\", " +
              "\"c\":\"{REDACTED}\", " +
              "\"d\":\"{REDACTED}\", " +
              "\"e\":\"{REDACTED}\", " +
              "\"f\":\"{REDACTED}\", " +
              "\"g\":\"{REDACTED}\", " +
              "\"h\":\"{REDACTED}\", " +
              "\"l\":\"{REDACTED}\" }");
    tokenizedObject = new JSONObject(syntax.redactComponents(multiFieldObject));

    assertFalse(syntax.valueStringIsCompletelyTokenized(
         singleFieldObject.toSingleLineString()));
    assertTrue(syntax.valueStringIsCompletelyTokenized(
         "{ \"tokenized\":\"{TOKENIZED:abcdef}\" }"));
    assertTrue(syntax.valueStringIsCompletelyTokenized(
         "{TOKENIZED:abcdef}"));

    assertTrue(syntax.completelyTokenizedValueConformsToSyntax());

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    String tokenizedString =
         syntax.tokenizeEntireValue(singleFieldObject, pepper);
    assertNotNull(tokenizedString);
    assertTrue(tokenizedString.startsWith("{ \"tokenized\":\"{TOKENIZED:"));
    assertTrue(tokenizedString.endsWith("}\" }"));
    tokenizedObject = new JSONObject(tokenizedString);

    assertTrue(syntax.supportsTokenizedComponents());

    assertTrue(syntax.valueWithTokenizedComponentsConformsToSyntax());

    tokenizedString = syntax.tokenizeComponents(singleFieldObject, pepper);
    tokenizedObject = new JSONObject(tokenizedString);
    assertEquals(tokenizedObject.getFields().size(), 1);
    assertNotNull(tokenizedObject.getFieldAsString("foo"));
    assertTrue(tokenizedObject.getFieldAsString("foo").startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedObject.getFieldAsString("foo").endsWith("}"));

    tokenizedString = syntax.tokenizeComponents(multiFieldObject, pepper);
    tokenizedObject = new JSONObject(tokenizedString);
    assertEquals(tokenizedObject.getFields().size(), 8);
    assertNotNull(tokenizedObject.getFieldAsString("a"));
    assertTrue(tokenizedObject.getFieldAsString("a").startsWith("{TOKENIZED:"));
    assertTrue(tokenizedObject.getFieldAsString("a").endsWith("}"));
    assertNotNull(tokenizedObject.getFieldAsString("c"));
    assertTrue(tokenizedObject.getFieldAsString("c").startsWith("{TOKENIZED:"));
    assertTrue(tokenizedObject.getFieldAsString("c").endsWith("}"));
    assertNotNull(tokenizedObject.getFieldAsString("d"));
    assertTrue(tokenizedObject.getFieldAsString("d").startsWith("{TOKENIZED:"));
    assertTrue(tokenizedObject.getFieldAsString("d").endsWith("}"));
    assertNotNull(tokenizedObject.getFieldAsString("e"));
    assertTrue(tokenizedObject.getFieldAsString("e").startsWith("{TOKENIZED:"));
    assertTrue(tokenizedObject.getFieldAsString("e").endsWith("}"));
    assertNotNull(tokenizedObject.getFieldAsString("f"));
    assertTrue(tokenizedObject.getFieldAsString("f").startsWith("{TOKENIZED:"));
    assertTrue(tokenizedObject.getFieldAsString("f").endsWith("}"));
    assertNotNull(tokenizedObject.getFieldAsString("g"));
    assertTrue(tokenizedObject.getFieldAsString("g").startsWith("{TOKENIZED:"));
    assertTrue(tokenizedObject.getFieldAsString("g").endsWith("}"));
    assertNotNull(tokenizedObject.getFieldAsString("h"));
    assertTrue(tokenizedObject.getFieldAsString("h").startsWith("{TOKENIZED:"));
    assertTrue(tokenizedObject.getFieldAsString("h").endsWith("}"));
    assertNotNull(tokenizedObject.getFieldAsString("l"));
    assertTrue(tokenizedObject.getFieldAsString("l").startsWith("{TOKENIZED:"));
    assertTrue(tokenizedObject.getFieldAsString("l").endsWith("}"));
  }



  /**
   * Tests the behavior for the syntax when it is configured to only consider
   * a specified set of fields as sensitive, and therefore only those fields
   * will be redacted or tokenized when operating on components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeFields()
         throws Exception
  {
    final Set<String> includeFields = StaticUtils.setOf("a", "b", "c");

    final JSONLogFieldSyntax syntax =
         new JSONLogFieldSyntax(10, includeFields, null);

    assertNotNull(syntax.getIncludedSensitiveFields());
    assertEquals(syntax.getIncludedSensitiveFields(), includeFields);

    assertNotNull(syntax.getExcludedSensitiveFields());
    assertTrue(syntax.getExcludedSensitiveFields().isEmpty());

    final JSONObject o = new JSONObject(
         new JSONField("a", "foo"),
         new JSONField("b", 5),
         new JSONField("c", true),
         new JSONField("d", "e"),
         new JSONField("f", new JSONObject(
              new JSONField("a", "g"),
              new JSONField("h", "i"))),
         new JSONField("j", new JSONArray(
              new JSONString("k"),
              new JSONObject(
                   new JSONField("a", "l"),
                   new JSONField("m", "n")))));

    assertNotNull(syntax.valueToSanitizedString(o));
    assertEquals(syntax.valueToSanitizedString(o),
         "{ \"a\":\"foo\", " +
              "\"b\":5, " +
              "\"c\":true, " +
              "\"d\":\"e\", " +
              "\"f\":{ \"a\":\"g\", \"h\":\"i\" }, " +
              "\"j\":[ \"k\", { \"a\":\"l\", \"m\":\"n\" } ] }");

    assertNotNull(syntax.redactComponents(o));
    assertEquals(syntax.redactComponents(o),
         "{ \"a\":\"{REDACTED}\", " +
              "\"b\":\"{REDACTED}\", " +
              "\"c\":\"{REDACTED}\", " +
              "\"d\":\"e\", " +
              "\"f\":{ \"a\":\"{REDACTED}\", \"h\":\"i\" }, " +
              "\"j\":[ \"k\", { \"a\":\"{REDACTED}\", \"m\":\"n\" } ] }");

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    assertNotNull(syntax.tokenizeComponents(o, pepper));
    final JSONObject tokenizedObject =
         new JSONObject(syntax.tokenizeComponents(o, pepper));
    assertEquals(tokenizedObject.getFields().size(), 6);
    assertNotNull(tokenizedObject.getFieldAsString("a"));
    assertTrue(tokenizedObject.getFieldAsString("a").startsWith("{TOKENIZED:"));
    assertNotNull(tokenizedObject.getFieldAsString("b"));
    assertTrue(tokenizedObject.getFieldAsString("b").startsWith("{TOKENIZED:"));
    assertNotNull(tokenizedObject.getFieldAsString("c"));
    assertTrue(tokenizedObject.getFieldAsString("c").startsWith("{TOKENIZED:"));
    assertNotNull(tokenizedObject.getFieldAsString("d"));
    assertEquals(tokenizedObject.getFieldAsString("d"), "e");

    final JSONObject tokenizedFObject = tokenizedObject.getFieldAsObject("f");
    assertNotNull(tokenizedFObject);
    assertEquals(tokenizedFObject.getFields().size(), 2);
    assertNotNull(tokenizedFObject.getFieldAsString("a"));
    assertTrue(tokenizedFObject.getFieldAsString("a").startsWith(
         "{TOKENIZED:"));
    assertNotNull(tokenizedFObject.getFieldAsString("h"));
    assertEquals(tokenizedFObject.getFieldAsString("h"), "i");

    final List<JSONValue> arrayElements = tokenizedObject.getFieldAsArray("j");
    assertNotNull(arrayElements);
    assertEquals(arrayElements.size(), 2);
    assertEquals(arrayElements.get(0), new JSONString("k"));

    final JSONObject arrayObject = (JSONObject) arrayElements.get(1);
    assertEquals(arrayObject.getFields().size(), 2);
    assertTrue(arrayObject.getFieldAsString("a").startsWith("{TOKENIZED:"));
    assertEquals(arrayObject.getFieldAsString("m"), "n");
  }



  /**
   * Tests the behavior for the syntax when it is configured to exclude a
   * specified set of fields as sensitive, and therefore only those fields will
   * not be redacted or tokenized when operating on components.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeFields()
         throws Exception
  {
    final Set<String> excludeFields = StaticUtils.setOf("a", "b", "c");

    final JSONLogFieldSyntax syntax =
         new JSONLogFieldSyntax(10, null, excludeFields);

    assertNotNull(syntax.getIncludedSensitiveFields());
    assertTrue(syntax.getIncludedSensitiveFields().isEmpty());

    assertNotNull(syntax.getExcludedSensitiveFields());
    assertEquals(syntax.getExcludedSensitiveFields(), excludeFields);

    final JSONObject o = new JSONObject(
         new JSONField("a", "foo"),
         new JSONField("b", 5),
         new JSONField("c", true),
         new JSONField("d", "e"),
         new JSONField("f", new JSONObject(
              new JSONField("a", "g"),
              new JSONField("h", "i"))),
         new JSONField("j", new JSONArray(
              new JSONString("k"),
              new JSONObject(
                   new JSONField("a", "l"),
                   new JSONField("m", "n")))));

    assertNotNull(syntax.valueToSanitizedString(o));
    assertEquals(syntax.valueToSanitizedString(o),
         "{ \"a\":\"foo\", " +
              "\"b\":5, " +
              "\"c\":true, " +
              "\"d\":\"e\", " +
              "\"f\":{ \"a\":\"g\", \"h\":\"i\" }, " +
              "\"j\":[ \"k\", { \"a\":\"l\", \"m\":\"n\" } ] }");

    assertNotNull(syntax.redactComponents(o));
    assertEquals(syntax.redactComponents(o),
         "{ \"a\":\"foo\", " +
              "\"b\":5, " +
              "\"c\":true, " +
              "\"d\":\"{REDACTED}\", " +
              "\"f\":\"{REDACTED}\", " +
              "\"j\":\"{REDACTED}\" }");

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    assertNotNull(syntax.tokenizeComponents(o, pepper));
    final JSONObject tokenizedObject =
         new JSONObject(syntax.tokenizeComponents(o, pepper));
    assertEquals(tokenizedObject.getFields().size(), 6);
    assertNotNull(tokenizedObject.getFieldAsString("a"));
    assertEquals(tokenizedObject.getFieldAsString("a"), "foo");
    assertNotNull(tokenizedObject.getFieldAsInteger("b"));
    assertEquals(tokenizedObject.getFieldAsInteger("b").intValue(), 5);
    assertNotNull(tokenizedObject.getFieldAsBoolean("c"));
    assertTrue(tokenizedObject.getFieldAsBoolean("c").booleanValue());
    assertNotNull(tokenizedObject.getFieldAsString("d"));
    assertTrue(tokenizedObject.getFieldAsString("d").startsWith("{TOKENIZED:"));
    assertNotNull(tokenizedObject.getFieldAsString("f"));
    assertTrue(tokenizedObject.getFieldAsString("f").startsWith("{TOKENIZED:"));
    assertNotNull(tokenizedObject.getFieldAsString("j"));
    assertTrue(tokenizedObject.getFieldAsString("j").startsWith("{TOKENIZED:"));
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
    final Set<String> includeFields = StaticUtils.setOf("a");
    final JSONLogFieldSyntax syntax =
         new JSONLogFieldSyntax(10, includeFields, null);

    final JSONObject o = new JSONObject(
         new JSONField("a", "foo"),
         new JSONField("b", "ThisIsALongerValue"));

    final ByteStringBuffer buffer = new ByteStringBuffer();
    syntax.logSanitizedFieldToTextFormattedLog("abc", o, buffer);
    assertEquals(buffer.toString(),
         " abc=\"{ 'a':'foo', 'b':'ThisIsALon{8 more characters}' }\"");

    buffer.clear();
    syntax.logCompletelyRedactedFieldToTextFormattedLog("def", buffer);
    assertEquals(buffer.toString(), " def=\"{ 'redacted':'{REDACTED}' }\"");

    buffer.clear();
    syntax.logRedactedComponentsFieldToTextFormattedLog("ghi", o, buffer);
    assertEquals(buffer.toString(),
         " ghi=\"{ 'a':'{REDACTED}', 'b':'ThisIsALon{8 more characters}' }\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToTextFormattedLog("jkl", o, pepper,
         buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         " jkl=\"{ 'tokenized':'{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}' }\""));

    buffer.clear();
    syntax.logTokenizedComponentsFieldToTextFormattedLog("mno", o, pepper,
         buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(
         " mno=\"{ 'a':'{TOKENIZED:"));
    assertTrue(tokenizedComponentsString.endsWith(
         "}', 'b':'ThisIsALon{8 more characters}' }\""));
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
    final Set<String> includeFields = StaticUtils.setOf("a");
    final JSONLogFieldSyntax syntax =
         new JSONLogFieldSyntax(10, includeFields, null);

    final JSONObject o = new JSONObject(
         new JSONField("a", "foo"),
         new JSONField("b", "ThisIsALongerValue"));

    final JSONBuffer buffer = new JSONBuffer();
    buffer.beginObject();
    syntax.logSanitizedFieldToJSONFormattedLog("abc", o, buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"abc\":{ \"a\":\"foo\", " +
              "\"b\":\"ThisIsALon{8 more characters}\" } }");

    buffer.clear();
    buffer.beginObject();
    syntax.logCompletelyRedactedFieldToJSONFormattedLog("def", buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"def\":{ \"redacted\":\"{REDACTED}\" } }");

    buffer.clear();
    buffer.beginObject();
    syntax.logRedactedComponentsFieldToJSONFormattedLog("ghi", o, buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"ghi\":{ \"a\":\"{REDACTED}\", " +
              "\"b\":\"ThisIsALon{8 more characters}\" } }");

    buffer.clear();
    buffer.beginObject();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToJSONFormattedLog("jkl", o, pepper,
         buffer);
    buffer.endObject();
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         "{ \"jkl\":{ \"tokenized\":\"{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\" } }"));

    buffer.clear();
    buffer.beginObject();
    syntax.logTokenizedComponentsFieldToJSONFormattedLog("mno", o, pepper,
         buffer);
    buffer.endObject();
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(
         "{ \"mno\":{ \"a\":\"{TOKENIZED:"));
    assertTrue(tokenizedComponentsString.endsWith(
         "}\", \"b\":\"ThisIsALon{8 more characters}\" } }"));
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
    final Set<String> includeFields = StaticUtils.setOf("a");
    final JSONLogFieldSyntax syntax =
         new JSONLogFieldSyntax(10, includeFields, null);

    final JSONObject o = new JSONObject(
         new JSONField("a", "foo"),
         new JSONField("b", "ThisIsALongerValue"));

    final JSONBuffer buffer = new JSONBuffer();
    syntax.logSanitizedValueToJSONFormattedLog(o, buffer);
    assertEquals(buffer.toString(),
         "{ \"a\":\"foo\", " +
              "\"b\":\"ThisIsALon{8 more characters}\" }");

    buffer.clear();
    syntax.logCompletelyRedactedValueToJSONFormattedLog(buffer);
    assertEquals(buffer.toString(),
         "{ \"redacted\":\"{REDACTED}\" }");

    buffer.clear();
    syntax.logRedactedComponentsValueToJSONFormattedLog(o, buffer);
    assertEquals(buffer.toString(),
         "{ \"a\":\"{REDACTED}\", " +
              "\"b\":\"ThisIsALon{8 more characters}\" }");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedValueToJSONFormattedLog(o, pepper, buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         "{ \"tokenized\":\"{TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\" }"));

    buffer.clear();
    syntax.logTokenizedComponentsValueToJSONFormattedLog(o, pepper, buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(
         "{ \"a\":\"{TOKENIZED:"));
    assertTrue(tokenizedComponentsString.endsWith(
         "}\", \"b\":\"ThisIsALon{8 more characters}\" }"));
  }
}
