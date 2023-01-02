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



import java.util.Collections;
import java.util.Set;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONBuffer;



/**
 * This class provides a set of test cases for the DN log field syntax.
 */
public final class DNLogFieldSyntaxTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the basic functionality of the syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasic()
         throws Exception
  {
    final DNLogFieldSyntax syntax = new DNLogFieldSyntax(10, null, null, null);

    assertEquals(syntax.getMaxStringLengthCharacters(), 10);

    assertNotNull(syntax.getIncludedSensitiveAttributes());
    assertTrue(syntax.getIncludedSensitiveAttributes().isEmpty());

    assertNotNull(syntax.getExcludedSensitiveAttributes());
    assertTrue(syntax.getExcludedSensitiveAttributes().isEmpty());

    assertNotNull(syntax.getSyntaxName());
    assertEquals(syntax.getSyntaxName(), "dn");

    assertNotNull(
         syntax.valueToSanitizedString(new DN("cn=test,dc=example,dc=com")));
    assertEquals(
         syntax.valueToSanitizedString(new DN("cn=test,dc=example,dc=com")),
         "cn=test,dc=example,dc=com");

    assertNotNull(
         syntax.valueToSanitizedString(new DN(
              "cn=ThisIsALongerValue,dc=example,dc=com")));
    assertEquals(
         syntax.valueToSanitizedString(new DN("" +
              "cn=ThisIsALongerValue,dc=example,dc=com")),
         "cn=ThisIsALon{8 more characters},dc=example,dc=com");

    assertNotNull(syntax.valueToSanitizedString(DN.NULL_DN));
    assertEquals(syntax.valueToSanitizedString(DN.NULL_DN), "");

    assertNotNull(syntax.parseValue("cn=test,dc=example,dc=com"));
    assertEquals(syntax.parseValue("cn=test,dc=example,dc=com"),
         new DN("cn=test,dc=example,dc=com"));

    assertNotNull(syntax.parseValue(""));
    assertEquals(syntax.parseValue(""), DN.NULL_DN);

    try
    {
      syntax.parseValue("{REDACTED}");
      fail("Expected an exception when trying to parse a redacted value");
    }
    catch (final RedactedValueException e)
    {
      // This was expected.
    }

    try
    {
      syntax.parseValue("{TOKENIZED:abcdef}");
      fail("Expected an exception when trying to parse a tokenized value");
    }
    catch (final TokenizedValueException e)
    {
      // This was expected.
    }

    try
    {
      syntax.parseValue("malformed");
      fail("Expected an exception when trying to parse a malformed value");
    }
    catch (final LogSyntaxException e)
    {
      assertFalse((e instanceof RedactedValueException) ||
           (e instanceof TokenizedValueException));
    }

    assertFalse(
         syntax.valueStringIsCompletelyRedacted("cn=test,dc=example,dc=com"));
    assertTrue(
         syntax.valueStringIsCompletelyRedacted("redacted={REDACTED}"));
    assertTrue(
         syntax.valueStringIsCompletelyRedacted("{REDACTED}"));

    assertTrue(syntax.completelyRedactedValueConformsToSyntax());

    assertNotNull(syntax.redactEntireValue());
    assertEquals(syntax.redactEntireValue(),
         "redacted={REDACTED}");

    assertTrue(syntax.supportsRedactedComponents());

    assertTrue(syntax.valueWithRedactedComponentsConformsToSyntax());

    assertNotNull(syntax.redactComponents(new DN("cn=test,dc=example,dc=com")));
    assertEquals(syntax.redactComponents(new DN("cn=test,dc=example,dc=com")),
         "cn={REDACTED},dc={REDACTED},dc={REDACTED}");

    assertNotNull(syntax.redactComponents(
         new DN("a=b+c=d+e=f,g=h+j=i,dc=example,dc=com")));
    assertEquals(
         syntax.redactComponents(new DN(
              "a=b+c=d+e=f,g=h+j=i,dc=example,dc=com")),
         "a={REDACTED}+c={REDACTED}+e={REDACTED},g={REDACTED}+j={REDACTED}," +
              "dc={REDACTED},dc={REDACTED}");

    assertNotNull(syntax.redactComponents(DN.NULL_DN));
    assertEquals(syntax.redactComponents(DN.NULL_DN), "");

    assertFalse(
         syntax.valueStringIsCompletelyTokenized("cn=test,dc=example,dc=com"));
    assertTrue(syntax.valueStringIsCompletelyTokenized(
         "tokenized={TOKENIZED:abcdef}"));
    assertTrue(syntax.valueStringIsCompletelyTokenized("{TOKENIZED:abcdef}"));

    assertTrue(syntax.completelyTokenizedValueConformsToSyntax());

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    String tokenizedValue = syntax.tokenizeEntireValue(
         new DN("cn=test,dc=example,dc=com"), pepper);
    assertNotNull(tokenizedValue);
    assertTrue(tokenizedValue.startsWith("tokenized={TOKENIZED:"));
    assertTrue(tokenizedValue.endsWith("}"));
    assertFalse(tokenizedValue.contains(","));

    assertTrue(syntax.supportsTokenizedComponents());

    assertTrue(syntax.valueWithTokenizedComponentsConformsToSyntax());

    tokenizedValue = syntax.tokenizeComponents(
         new DN("cn=test,dc=example,dc=com"), pepper);
    assertNotNull(tokenizedValue);
    DN tokenizedDN = new DN(tokenizedValue);
    RDN[] tokenizedRDNs = tokenizedDN.getRDNs();
    assertEquals(tokenizedRDNs.length, 3);
    assertEquals(tokenizedRDNs[0].getValueCount(), 1);
    assertEquals(tokenizedRDNs[0].getAttributeNames()[0], "cn");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].endsWith("}"));
    assertEquals(tokenizedRDNs[1].getValueCount(), 1);
    assertEquals(tokenizedRDNs[1].getAttributeNames()[0], "dc");
    assertTrue(tokenizedRDNs[1].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[1].getAttributeValues()[0].endsWith("}"));
    assertEquals(tokenizedRDNs[2].getValueCount(), 1);
    assertEquals(tokenizedRDNs[2].getAttributeNames()[0], "dc");
    assertTrue(tokenizedRDNs[2].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[2].getAttributeValues()[0].endsWith("}"));

    tokenizedValue = syntax.tokenizeComponents(
         new DN("a=b+c=d+e=f,g=h+j=i,dc=example,dc=com"), pepper);
    assertNotNull(tokenizedValue);
    tokenizedDN = new DN(tokenizedValue);
    tokenizedRDNs = tokenizedDN.getRDNs();
    assertEquals(tokenizedRDNs.length, 4);
    assertEquals(tokenizedRDNs[0].getValueCount(), 3);
    assertEquals(tokenizedRDNs[0].getAttributeNames()[0], "a");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].endsWith("}"));
    assertEquals(tokenizedRDNs[0].getAttributeNames()[1], "c");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[1].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[1].endsWith("}"));
    assertEquals(tokenizedRDNs[0].getAttributeNames()[2], "e");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[2].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[2].endsWith("}"));
    assertEquals(tokenizedRDNs[1].getValueCount(), 2);
    assertEquals(tokenizedRDNs[1].getAttributeNames()[0], "g");
    assertTrue(tokenizedRDNs[1].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[1].getAttributeValues()[0].endsWith("}"));
    assertEquals(tokenizedRDNs[1].getAttributeNames()[1], "j");
    assertTrue(tokenizedRDNs[1].getAttributeValues()[1].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[1].getAttributeValues()[1].endsWith("}"));
    assertEquals(tokenizedRDNs[2].getValueCount(), 1);
    assertEquals(tokenizedRDNs[2].getAttributeNames()[0], "dc");
    assertTrue(tokenizedRDNs[2].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[2].getAttributeValues()[0].endsWith("}"));
    assertEquals(tokenizedRDNs[3].getValueCount(), 1);
    assertEquals(tokenizedRDNs[3].getAttributeNames()[0], "dc");
    assertTrue(tokenizedRDNs[3].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[3].getAttributeValues()[0].endsWith("}"));

    tokenizedValue = syntax.tokenizeComponents(DN.NULL_DN, pepper);
    assertNotNull(tokenizedValue);
    assertEquals(tokenizedValue, "");
  }



  /**
   * Tests the behavior with a set of included sensitive attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludedSensitiveAttributes()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();

    final Set<String> includedAttributes = StaticUtils.setOf("cn", "ou");
    final Set<String> excludedAttributes = Collections.emptySet();

    final DNLogFieldSyntax syntax = new DNLogFieldSyntax(10, schema,
         includedAttributes, excludedAttributes);

    assertEquals(syntax.getMaxStringLengthCharacters(), 10);

    assertNotNull(syntax.getIncludedSensitiveAttributes());
    assertFalse(syntax.getIncludedSensitiveAttributes().isEmpty());
    assertTrue(syntax.getIncludedSensitiveAttributes().contains("cn"));
    assertTrue(syntax.getIncludedSensitiveAttributes().contains("ou"));
    // Since we provided a schema, there should also be the attr type OIDs.
    assertTrue(syntax.getIncludedSensitiveAttributes().contains("2.5.4.3"));
    assertTrue(syntax.getIncludedSensitiveAttributes().contains("2.5.4.11"));

    assertNotNull(syntax.getExcludedSensitiveAttributes());
    assertTrue(syntax.getExcludedSensitiveAttributes().isEmpty());


    assertNotNull(
         syntax.valueToSanitizedString(new DN("cn=test,dc=example,dc=com")));
    assertEquals(
         syntax.valueToSanitizedString(new DN("cn=test,dc=example,dc=com")),
         "cn=test,dc=example,dc=com");


    assertNotNull(syntax.redactComponents(new DN("cn=test,dc=example,dc=com")));
    assertEquals(syntax.redactComponents(new DN("cn=test,dc=example,dc=com")),
         "cn={REDACTED},dc=example,dc=com");

    assertNotNull(syntax.redactComponents(
         new DN("cn=test1+ou=test2,dc=example,dc=com")));
    assertEquals(
         syntax.redactComponents(new DN("cn=test1+ou=test2,dc=example,dc=com")),
         "cn={REDACTED}+ou={REDACTED},dc=example,dc=com");

    assertNotNull(syntax.redactComponents(
         new DN("cn=test1+givenName=test2,dc=example,dc=com")));
    assertEquals(
         syntax.redactComponents(new DN(
              "cn=test1+givenName=test2,dc=example,dc=com")),
         "cn={REDACTED}+givenName=test2,dc=example,dc=com");



    final byte[] pepper = StaticUtils.randomBytes(8, false);
    String tokenizedValue =
         syntax.tokenizeComponents(new DN("cn=test,dc=example,dc=com"), pepper);
    DN tokenizedDN = new DN(tokenizedValue);
    RDN[] tokenizedRDNs = tokenizedDN.getRDNs();
    assertEquals(tokenizedRDNs.length, 3);
    assertEquals(tokenizedRDNs[0].getValueCount(), 1);
    assertEquals(tokenizedRDNs[0].getAttributeNames()[0], "cn");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].endsWith("}"));
    assertEquals(tokenizedRDNs[1].getValueCount(), 1);
    assertEquals(tokenizedRDNs[1].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[1].getAttributeValues()[0], "example");
    assertEquals(tokenizedRDNs[2].getValueCount(), 1);
    assertEquals(tokenizedRDNs[2].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[2].getAttributeValues()[0], "com");

    tokenizedValue = syntax.tokenizeComponents(
         new DN("cn=test1+ou=test2,dc=example,dc=com"), pepper);
    tokenizedDN = new DN(tokenizedValue);
    tokenizedRDNs = tokenizedDN.getRDNs();
    assertEquals(tokenizedRDNs.length, 3);
    assertEquals(tokenizedRDNs[0].getValueCount(), 2);
    assertEquals(tokenizedRDNs[0].getAttributeNames()[0], "cn");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].endsWith("}"));
    assertEquals(tokenizedRDNs[0].getAttributeNames()[1], "ou");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[1].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[1].endsWith("}"));
    assertEquals(tokenizedRDNs[1].getValueCount(), 1);
    assertEquals(tokenizedRDNs[1].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[1].getAttributeValues()[0], "example");
    assertEquals(tokenizedRDNs[2].getValueCount(), 1);
    assertEquals(tokenizedRDNs[2].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[2].getAttributeValues()[0], "com");

    tokenizedValue = syntax.tokenizeComponents(
         new DN("cn=test1+givenName=test2,dc=example,dc=com"), pepper);
    tokenizedDN = new DN(tokenizedValue);
    tokenizedRDNs = tokenizedDN.getRDNs();
    assertEquals(tokenizedRDNs.length, 3);
    assertEquals(tokenizedRDNs[0].getValueCount(), 2);
    assertEquals(tokenizedRDNs[0].getAttributeNames()[0], "cn");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].endsWith("}"));
    assertEquals(tokenizedRDNs[0].getAttributeNames()[1], "givenName");
    assertEquals(tokenizedRDNs[0].getAttributeValues()[1], "test2");
    assertEquals(tokenizedRDNs[1].getValueCount(), 1);
    assertEquals(tokenizedRDNs[1].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[1].getAttributeValues()[0], "example");
    assertEquals(tokenizedRDNs[2].getValueCount(), 1);
    assertEquals(tokenizedRDNs[2].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[2].getAttributeValues()[0], "com");
  }



  /**
   * Tests the behavior with a set of excluded sensitive attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludedSensitiveAttributes()
         throws Exception
  {
    final Set<String> includedAttributes = Collections.emptySet();
    final Set<String> excludedAttributes = StaticUtils.setOf("dc", "ou");

    final DNLogFieldSyntax syntax = new DNLogFieldSyntax(10, null,
         includedAttributes, excludedAttributes);

    assertEquals(syntax.getMaxStringLengthCharacters(), 10);

    assertNotNull(syntax.getIncludedSensitiveAttributes());
    assertTrue(syntax.getIncludedSensitiveAttributes().isEmpty());

    assertNotNull(syntax.getExcludedSensitiveAttributes());
    assertFalse(syntax.getExcludedSensitiveAttributes().isEmpty());
    assertTrue(syntax.getExcludedSensitiveAttributes().contains("dc"));
    assertTrue(syntax.getExcludedSensitiveAttributes().contains("ou"));


    assertNotNull(
         syntax.valueToSanitizedString(new DN("cn=test,dc=example,dc=com")));
    assertEquals(
         syntax.valueToSanitizedString(new DN("cn=test,dc=example,dc=com")),
         "cn=test,dc=example,dc=com");


    assertNotNull(syntax.redactComponents(new DN("cn=test,dc=example,dc=com")));
    assertEquals(syntax.redactComponents(new DN("cn=test,dc=example,dc=com")),
         "cn={REDACTED},dc=example,dc=com");

    assertNotNull(syntax.redactComponents(
         new DN("cn=test1+ou=test2,dc=example,dc=com")));
    assertEquals(
         syntax.redactComponents(new DN("cn=test1+ou=test2,dc=example,dc=com")),
         "cn={REDACTED}+ou=test2,dc=example,dc=com");

    assertNotNull(syntax.redactComponents(
         new DN("cn=test1+givenName=test2,dc=example,dc=com")));
    assertEquals(
         syntax.redactComponents(new DN(
              "cn=test1+givenName=test2,dc=example,dc=com")),
         "cn={REDACTED}+givenName={REDACTED},dc=example,dc=com");



    final byte[] pepper = StaticUtils.randomBytes(8, false);
    String tokenizedValue =
         syntax.tokenizeComponents(new DN("cn=test,dc=example,dc=com"), pepper);
    DN tokenizedDN = new DN(tokenizedValue);
    RDN[] tokenizedRDNs = tokenizedDN.getRDNs();
    assertEquals(tokenizedRDNs.length, 3);
    assertEquals(tokenizedRDNs[0].getValueCount(), 1);
    assertEquals(tokenizedRDNs[0].getAttributeNames()[0], "cn");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].endsWith("}"));
    assertEquals(tokenizedRDNs[1].getValueCount(), 1);
    assertEquals(tokenizedRDNs[1].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[1].getAttributeValues()[0], "example");
    assertEquals(tokenizedRDNs[2].getValueCount(), 1);
    assertEquals(tokenizedRDNs[2].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[2].getAttributeValues()[0], "com");

    tokenizedValue = syntax.tokenizeComponents(
         new DN("cn=test1+ou=test2,dc=example,dc=com"), pepper);
    tokenizedDN = new DN(tokenizedValue);
    tokenizedRDNs = tokenizedDN.getRDNs();
    assertEquals(tokenizedRDNs.length, 3);
    assertEquals(tokenizedRDNs[0].getValueCount(), 2);
    assertEquals(tokenizedRDNs[0].getAttributeNames()[0], "cn");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].endsWith("}"));
    assertEquals(tokenizedRDNs[0].getAttributeNames()[1], "ou");
    assertEquals(tokenizedRDNs[0].getAttributeValues()[1], "test2");
    assertEquals(tokenizedRDNs[1].getValueCount(), 1);
    assertEquals(tokenizedRDNs[1].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[1].getAttributeValues()[0], "example");
    assertEquals(tokenizedRDNs[2].getValueCount(), 1);
    assertEquals(tokenizedRDNs[2].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[2].getAttributeValues()[0], "com");

    tokenizedValue = syntax.tokenizeComponents(
         new DN("cn=test1+givenName=test2,dc=example,dc=com"), pepper);
    tokenizedDN = new DN(tokenizedValue);
    tokenizedRDNs = tokenizedDN.getRDNs();
    assertEquals(tokenizedRDNs.length, 3);
    assertEquals(tokenizedRDNs[0].getValueCount(), 2);
    assertEquals(tokenizedRDNs[0].getAttributeNames()[0], "cn");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[0].endsWith("}"));
    assertEquals(tokenizedRDNs[0].getAttributeNames()[1], "givenName");
    assertTrue(tokenizedRDNs[0].getAttributeValues()[1].startsWith(
         "{TOKENIZED:"));
    assertTrue(tokenizedRDNs[0].getAttributeValues()[1].endsWith("}"));
    assertEquals(tokenizedRDNs[1].getValueCount(), 1);
    assertEquals(tokenizedRDNs[1].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[1].getAttributeValues()[0], "example");
    assertEquals(tokenizedRDNs[2].getValueCount(), 1);
    assertEquals(tokenizedRDNs[2].getAttributeNames()[0], "dc");
    assertEquals(tokenizedRDNs[2].getAttributeValues()[0], "com");
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
    final Set<String> includedAttributes = StaticUtils.setOf("uid");
    final Set<String> excludedAttributes = Collections.emptySet();
    final DNLogFieldSyntax syntax = new DNLogFieldSyntax(100, null,
         includedAttributes, excludedAttributes);

    final ByteStringBuffer buffer = new ByteStringBuffer();
    syntax.logSanitizedFieldToTextFormattedLog("abc",
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         buffer);
    assertEquals(buffer.toString(),
         " abc=\"uid=test.user,ou=People,dc=example,dc=com\"");

    buffer.clear();
    syntax.logCompletelyRedactedFieldToTextFormattedLog("def", buffer);
    assertEquals(buffer.toString(), " def=\"redacted={REDACTED}\"");

    buffer.clear();
    syntax.logRedactedComponentsFieldToTextFormattedLog("ghi",
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         buffer);
    assertEquals(buffer.toString(),
         " ghi=\"uid={REDACTED},ou=People,dc=example,dc=com\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToTextFormattedLog("jkl",
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         pepper, buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         " jkl=\"tokenized={TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\""));

    buffer.clear();
    syntax.logTokenizedComponentsFieldToTextFormattedLog("mno",
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         pepper, buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(" mno=\"uid={TOKENIZED:"));
    assertTrue(tokenizedComponentsString.endsWith(
         "},ou=People,dc=example,dc=com\""));
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
    final Set<String> includedAttributes = StaticUtils.setOf("uid");
    final Set<String> excludedAttributes = Collections.emptySet();
    final DNLogFieldSyntax syntax = new DNLogFieldSyntax(100, null,
         includedAttributes, excludedAttributes);

    final JSONBuffer buffer = new JSONBuffer();
    buffer.beginObject();
    syntax.logSanitizedFieldToJSONFormattedLog("abc",
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"abc\":\"uid=test.user,ou=People,dc=example,dc=com\" }");

    buffer.clear();
    buffer.beginObject();
    syntax.logCompletelyRedactedFieldToJSONFormattedLog("def", buffer);
    buffer.endObject();
    assertEquals(buffer.toString(), "{ \"def\":\"redacted={REDACTED}\" }");

    buffer.clear();
    buffer.beginObject();
    syntax.logRedactedComponentsFieldToJSONFormattedLog("ghi",
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"ghi\":\"uid={REDACTED},ou=People,dc=example,dc=com\" }");

    buffer.clear();
    buffer.beginObject();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToJSONFormattedLog("jkl",
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         pepper, buffer);
    buffer.endObject();
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         "{ \"jkl\":\"tokenized={TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\" }"));

    buffer.clear();
    buffer.beginObject();
    syntax.logTokenizedComponentsFieldToJSONFormattedLog("mno",
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         pepper, buffer);
    buffer.endObject();
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(
         "{ \"mno\":\"uid={TOKENIZED:"));
    assertTrue(tokenizedComponentsString.endsWith(
         "},ou=People,dc=example,dc=com\" }"));
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
    final Set<String> includedAttributes = StaticUtils.setOf("uid");
    final Set<String> excludedAttributes = Collections.emptySet();
    final DNLogFieldSyntax syntax = new DNLogFieldSyntax(100, null,
         includedAttributes, excludedAttributes);

    final JSONBuffer buffer = new JSONBuffer();
    syntax.logSanitizedValueToJSONFormattedLog(
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         buffer);
    assertEquals(buffer.toString(),
         "\"uid=test.user,ou=People,dc=example,dc=com\"");

    buffer.clear();
    syntax.logCompletelyRedactedValueToJSONFormattedLog(buffer);
    assertEquals(buffer.toString(), "\"redacted={REDACTED}\"");

    buffer.clear();
    syntax.logRedactedComponentsValueToJSONFormattedLog(
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         buffer);
    assertEquals(buffer.toString(),
         "\"uid={REDACTED},ou=People,dc=example,dc=com\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedValueToJSONFormattedLog(
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         pepper, buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         "\"tokenized={TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("}\""));

    buffer.clear();
    syntax.logTokenizedComponentsValueToJSONFormattedLog(
         new DN("uid=test.user,ou=People,dc=example,dc=com"),
         pepper, buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(
         "\"uid={TOKENIZED:"));
    assertTrue(tokenizedComponentsString.endsWith(
         "},ou=People,dc=example,dc=com\""));
  }
}
