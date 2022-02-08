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



import java.util.Collections;
import java.util.Set;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONBuffer;



/**
 * This class provides a set of test cases for the filter log field syntax.
 */
public final class FilterLogFieldSyntaxTestCase
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
    final FilterLogFieldSyntax syntax =
         new FilterLogFieldSyntax(10, null, null, null);

    assertEquals(syntax.getMaxStringLengthCharacters(), 10);

    assertNotNull(syntax.getIncludedSensitiveAttributes());
    assertTrue(syntax.getIncludedSensitiveAttributes().isEmpty());

    assertNotNull(syntax.getExcludedSensitiveAttributes());
    assertTrue(syntax.getExcludedSensitiveAttributes().isEmpty());

    assertNotNull(syntax.getSyntaxName());
    assertEquals(syntax.getSyntaxName(), "filter");

    assertNotNull(
         syntax.valueToSanitizedString(
              Filter.createEqualityFilter("uid", "test")));
    assertEquals(
         syntax.valueToSanitizedString(
              Filter.createEqualityFilter("uid", "test")),
         "(uid=test)");

    assertNotNull(
         syntax.valueToSanitizedString(
              Filter.createEqualityFilter("uid", "ThisIsALongerValue")));
    assertEquals(
         syntax.valueToSanitizedString(
              Filter.createEqualityFilter("uid", "ThisIsALongerValue")),
         "(uid=ThisIsALon{8 more characters})");

    assertNotNull(syntax.parseValue("(uid=test)"));
    assertEquals(syntax.parseValue("(uid=test)"),
         Filter.createEqualityFilter("uid", "test"));

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
         syntax.valueStringIsCompletelyRedacted("(uid=test)"));
    assertTrue(
         syntax.valueStringIsCompletelyRedacted("(redacted={REDACTED})"));
    assertTrue(
         syntax.valueStringIsCompletelyRedacted("{REDACTED}"));

    assertTrue(syntax.completelyRedactedValueConformsToSyntax());

    assertNotNull(syntax.redactEntireValue());
    assertEquals(syntax.redactEntireValue(),
         "(redacted={REDACTED})");

    assertTrue(syntax.supportsRedactedComponents());

    assertTrue(syntax.valueWithRedactedComponentsConformsToSyntax());

    assertNotNull(
         syntax.redactComponents(Filter.createEqualityFilter("uid", "test")));
    assertEquals(
         syntax.redactComponents(Filter.createEqualityFilter("uid", "test")),
         "(uid={REDACTED})");

    assertFalse(
         syntax.valueStringIsCompletelyTokenized("(uid=test)"));
    assertTrue(syntax.valueStringIsCompletelyTokenized(
         "(tokenized={TOKENIZED:abcdef})"));
    assertTrue(syntax.valueStringIsCompletelyTokenized("{TOKENIZED:abcdef}"));

    assertTrue(syntax.completelyTokenizedValueConformsToSyntax());

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    String tokenizedValue = syntax.tokenizeEntireValue(
         Filter.createEqualityFilter("uid", "test"), pepper);
    assertNotNull(tokenizedValue);
    assertTrue(tokenizedValue.startsWith("(tokenized={TOKENIZED:"));
    assertTrue(tokenizedValue.endsWith("})"));

    assertTrue(syntax.supportsTokenizedComponents());

    assertTrue(syntax.valueWithTokenizedComponentsConformsToSyntax());

    tokenizedValue = syntax.tokenizeComponents(
         Filter.createEqualityFilter("uid", "test"), pepper);
    assertTrue(tokenizedValue.startsWith("(uid={TOKENIZED:"));
    assertTrue(tokenizedValue.endsWith("})"));
    assertNotNull(tokenizedValue);
    Filter tokenizedFilter = Filter.create(tokenizedValue);
    assertEquals(tokenizedFilter.getFilterType(), Filter.FILTER_TYPE_EQUALITY);
    assertEquals(tokenizedFilter.getAttributeName(), "uid");
    assertTrue(tokenizedFilter.getAssertionValue().startsWith("{TOKENIZED:"));
    assertTrue(tokenizedFilter.getAssertionValue().endsWith("}"));
  }



  /**
   * Tests sanitization, redaction, and tokenization for components of various
   * types of filters.
   *
   * @param  filterString               The string representation of the filter
   *                                    to test.
   * @param  expectedSanitizedString    The expected string representation for
   *                                    the sanitized filter.
   * @param  expectedRedactedAllTypes   The expected string representation for a
   *                                    filter with redacted components when
   *                                    values should be redacted for all types.
   * @param  expectedRedactedOnlyA      The expected string representation for a
   *                                    filter with redacted components when
   *                                    values should only be redacted for the
   *                                    'a' attribute type.
   * @param  expectedRedactedAllButA    The expected string representation for a
   *                                    filter with redacted components when
   *                                    values should be redacted for all
   *                                    attribute types except 'a'.
   * @param  expectedTokenizedAllTypes  The expected string representation for a
   *                                    filter with tokenized components when
   *                                    values should be tokenized for all
   *                                    types.
   * @param  expectedTokenizedOnlyA     The expected string representation for a
   *                                    filter with tokenized components when
   *                                    values should only be tokenized for the
   *                                    'a' attribute type.
   * @param  expectedTokenizedAllButA   The expected string representation for a
   *                                    filter with tokenized components when
   *                                    values should be tokenized for all
   *                                    attribute types except 'a'.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="filterTypeTestData")
  public void testFilterTypes(final String filterString,
                              final String expectedSanitizedString,
                              final String expectedRedactedAllTypes,
                              final String expectedRedactedOnlyA,
                              final String expectedRedactedAllButA,
                              final String[] expectedTokenizedAllTypes,
                              final String[] expectedTokenizedOnlyA,
                              final String[] expectedTokenizedAllButA)
         throws Exception
  {
    // Test with a syntax that doesn't have any included or excluded sensitive
    // attribute types.
    final FilterLogFieldSyntax syntaxForAllTypes =
         new FilterLogFieldSyntax(10, null, null, null);

    final Filter filter = Filter.create(filterString);

    assertEquals(syntaxForAllTypes.valueToSanitizedString(filter),
         expectedSanitizedString);

    assertEquals(syntaxForAllTypes.redactComponents(filter),
         expectedRedactedAllTypes);

    final byte[] pepper = StaticUtils.randomBytes(8, false);
    String tokenizedComponentsString =
         syntaxForAllTypes.tokenizeComponents(filter, pepper);
    assertTrue(
         tokenizedComponentsString.startsWith(expectedTokenizedAllTypes[0]),
         tokenizedComponentsString);
    assertTrue(
         tokenizedComponentsString.endsWith(
              expectedTokenizedAllTypes[
                   expectedTokenizedAllTypes.length - 1]),
         tokenizedComponentsString);

    int lastPos = -1;
    for (final String comp : expectedTokenizedAllTypes)
    {
      final int pos = tokenizedComponentsString.indexOf(comp, (lastPos+1));
      assertTrue((pos > lastPos), comp);
      lastPos = pos;
    }


    // Test with a syntax that includes only the 'a' attribute type.
    final FilterLogFieldSyntax syntaxIncludesA =
         new FilterLogFieldSyntax(10, Schema.getDefaultStandardSchema(),
              Collections.singleton("a"), null);

    assertEquals(syntaxIncludesA.valueToSanitizedString(filter),
         expectedSanitizedString);

    assertEquals(syntaxIncludesA.redactComponents(filter),
         expectedRedactedOnlyA);

    tokenizedComponentsString =
         syntaxIncludesA.tokenizeComponents(filter, pepper);
    assertTrue(
         tokenizedComponentsString.startsWith(expectedTokenizedOnlyA[0]),
         tokenizedComponentsString);
    assertTrue(
         tokenizedComponentsString.endsWith(
              expectedTokenizedOnlyA[
                   expectedTokenizedOnlyA.length - 1]),
         tokenizedComponentsString);

    lastPos = -1;
    for (final String comp : expectedTokenizedOnlyA)
    {
      final int pos = tokenizedComponentsString.indexOf(comp, (lastPos+1));
      assertTrue((pos > lastPos), comp);
      lastPos = pos;
    }


    // Test with a syntax that excludes only the 'a' attribute type.
    final FilterLogFieldSyntax syntaxExcludesA =
         new FilterLogFieldSyntax(10, null, null,
              Collections.singleton("a"));

    assertEquals(syntaxExcludesA.valueToSanitizedString(filter),
         expectedSanitizedString);

    assertEquals(syntaxExcludesA.redactComponents(filter),
         expectedRedactedAllButA);

    tokenizedComponentsString =
         syntaxExcludesA.tokenizeComponents(filter, pepper);
    assertTrue(
         tokenizedComponentsString.startsWith(expectedTokenizedAllButA[0]),
         tokenizedComponentsString);
    assertTrue(
         tokenizedComponentsString.endsWith(
              expectedTokenizedAllButA[
                   expectedTokenizedAllButA.length - 1]),
         tokenizedComponentsString);

    lastPos = -1;
    for (final String comp : expectedTokenizedAllButA)
    {
      final int pos = tokenizedComponentsString.indexOf(comp, (lastPos+1));
      assertTrue((pos > lastPos), comp);
      lastPos = pos;
    }
  }



  /**
   * Retrieves a set of test data that can be used for testing sanitization,
   * redaction, and tokenization for a variety of filter types.
   *
   * @return  The test data that was created.
   */
  @DataProvider(name="filterTypeTestData")
  public Object[][] getFilterTypeTestData()
  {
    return new Object[][]
    {
      // A presence filter that won't be altered.
      new Object[]
      {
        "(a=*)",
        "(a=*)",
        "(a=*)",
        "(a=*)",
        "(a=*)",
        new String[]
        {
          "(a=*)"
        },
        new String[]
        {
          "(a=*)"
        },
        new String[]
        {
          "(a=*)"
        }
      },

      // An equality filter that won't be truncated.
      new Object[]
      {
        "(a=test)",
        "(a=test)",
        "(a={REDACTED})",
        "(a={REDACTED})",
        "(a=test)",
        new String[]
        {
          "(a={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a=test)"
        }
      },

      // An equality filter that will be truncated.
      new Object[]
      {
        "(a=ThisIsALongerValue)",
        "(a=ThisIsALon{8 more characters})",
        "(a={REDACTED})",
        "(a={REDACTED})",
        "(a=ThisIsALon{8 more characters})",
        new String[]
        {
          "(a={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a=ThisIsALon{8 more characters})"
        }
      },

      // A greater-or-equal filter that won't be truncated.
      new Object[]
      {
        "(a>=test)",
        "(a>=test)",
        "(a>={REDACTED})",
        "(a>={REDACTED})",
        "(a>=test)",
        new String[]
        {
          "(a>={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a>={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a>=test)"
        }
      },

      // A greater-or-equal filter that will be truncated.
      new Object[]
      {
        "(a>=ThisIsALongerValue)",
        "(a>=ThisIsALon{8 more characters})",
        "(a>={REDACTED})",
        "(a>={REDACTED})",
        "(a>=ThisIsALon{8 more characters})",
        new String[]
        {
          "(a>={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a>={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a>=ThisIsALon{8 more characters})"
        }
      },

      // A less-or-equal filter that won't be truncated.
      new Object[]
      {
        "(a<=test)",
        "(a<=test)",
        "(a<={REDACTED})",
        "(a<={REDACTED})",
        "(a<=test)",
        new String[]
        {
          "(a<={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a<={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a<=test)"
        }
      },

      // A less-or-equal filter that will be truncated.
      new Object[]
      {
        "(a<=ThisIsALongerValue)",
        "(a<=ThisIsALon{8 more characters})",
        "(a<={REDACTED})",
        "(a<={REDACTED})",
        "(a<=ThisIsALon{8 more characters})",
        new String[]
        {
          "(a<={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a<={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a<=ThisIsALon{8 more characters})"
        }
      },

      // An approximate-match filter that won't be truncated.
      new Object[]
      {
        "(a~=test)",
        "(a~=test)",
        "(a~={REDACTED})",
        "(a~={REDACTED})",
        "(a~=test)",
        new String[]
        {
          "(a~={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a~={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a~=test)"
        }
      },

      // A less-or-equal filter that will be truncated.
      new Object[]
      {
        "(a<=ThisIsALongerValue)",
        "(a<=ThisIsALon{8 more characters})",
        "(a<={REDACTED})",
        "(a<={REDACTED})",
        "(a<=ThisIsALon{8 more characters})",
        new String[]
        {
          "(a<={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a<={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a<=ThisIsALon{8 more characters})"
        }
      },

      // An extensible match filter with an attribute type but no matching rule
      // ID or DN attributes flag.
      new Object[]
      {
        "(a:=test)",
        "(a:=test)",
        "(a:={REDACTED})",
        "(a:={REDACTED})",
        "(a:=test)",
        new String[]
        {
          "(a:={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a:={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a:=test)"
        }
      },

      // An extensible match filter with a matching rule ID but no attribute
      // type or DN attributes flag.
      new Object[]
      {
        "(:caseIgnoreMatch:=ThisIsALongerValue)",
        "(:caseIgnoreMatch:=ThisIsALon{8 more characters})",
        "(:caseIgnoreMatch:={REDACTED})",
        "(:caseIgnoreMatch:=ThisIsALon{8 more characters})",
        "(:caseIgnoreMatch:={REDACTED})",
        new String[]
        {
          "(:caseIgnoreMatch:={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(:caseIgnoreMatch:=ThisIsALon{8 more characters})"
        },
        new String[]
        {
          "(:caseIgnoreMatch:={TOKENIZED:",
          "})"
        }
      },

      // An extensible match filter with an attribute type, matching rule ID,
      // and DN attributes flag.
      new Object[]
      {
        "(a:caseIgnoreMatch:dn:=test)",
        "(a:caseIgnoreMatch:dn:=test)",
        "(a:caseIgnoreMatch:dn:={REDACTED})",
        "(a:caseIgnoreMatch:dn:={REDACTED})",
        "(a:caseIgnoreMatch:dn:=test)",
        new String[]
        {
          "(a:caseIgnoreMatch:dn:={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a:caseIgnoreMatch:dn:={TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a:caseIgnoreMatch:dn:=test)"
        }
      },

      // A substring filter with just a subInitial component.
      new Object[]
      {
        "(a=test*)",
        "(a=test*)",
        "(a={REDACTED}*)",
        "(a={REDACTED}*)",
        "(a=test*)",
        new String[]
        {
          "(a={TOKENIZED:",
          "}*)"
        },
        new String[]
        {
          "(a={TOKENIZED:",
          "}*)"
        },
        new String[]
        {
          "(a=test*)"
        }
      },

      // A substring filter with just a subAny component.
      new Object[]
      {
        "(a=*ThisIsALongerValue*)",
        "(a=*ThisIsALon{8 more characters}*)",
        "(a=*{REDACTED}*)",
        "(a=*{REDACTED}*)",
        "(a=*ThisIsALon{8 more characters}*)",
        new String[]
        {
          "(a=*{TOKENIZED:",
          "}*)"
        },
        new String[]
        {
          "(a=*{TOKENIZED:",
          "}*)"
        },
        new String[]
        {
          "(a=*ThisIsALon{8 more characters}*)"
        }
      },

      // A substring filter with just a subFinal component.
      new Object[]
      {
        "(a=*test)",
        "(a=*test)",
        "(a=*{REDACTED})",
        "(a=*{REDACTED})",
        "(a=*test)",
        new String[]
        {
          "(a=*{TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a=*{TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a=*test)"
        }
      },

      // A substring filter with all component types.
      new Object[]
      {
        "(a=b*c*d*e)",
        "(a=b*c*d*e)",
        "(a={REDACTED}*{REDACTED}*{REDACTED}*{REDACTED})",
        "(a={REDACTED}*{REDACTED}*{REDACTED}*{REDACTED})",
        "(a=b*c*d*e)",
        new String[]
        {
          "(a={TOKENIZED:",
          "}*{TOKENIZED:",
          "}*{TOKENIZED:",
          "}*{TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a={TOKENIZED:",
          "}*{TOKENIZED:",
          "}*{TOKENIZED:",
          "}*{TOKENIZED:",
          "})"
        },
        new String[]
        {
          "(a=b*c*d*e)"
        }
      },

      // An AND filter.
      new Object[]
      {
        "(&(a=b)(c>=d)(e<=f)(g~=h)(i:=j)(k=l*m*n))",
        "(&(a=b)(c>=d)(e<=f)(g~=h)(i:=j)(k=l*m*n))",
        "(&(a={REDACTED})(c>={REDACTED})(e<={REDACTED})(g~={REDACTED})" +
             "(i:={REDACTED})(k={REDACTED}*{REDACTED}*{REDACTED}))",
        "(&(a={REDACTED})(c>=d)(e<=f)(g~=h)(i:=j)(k=l*m*n))",
        "(&(a=b)(c>={REDACTED})(e<={REDACTED})(g~={REDACTED})" +
             "(i:={REDACTED})(k={REDACTED}*{REDACTED}*{REDACTED}))",
        new String[]
        {
          "(&(a={TOKENIZED:",
          "})(c>={TOKENIZED:",
          "})(e<={TOKENIZED:",
          "})(g~={TOKENIZED:",
          "})(i:={TOKENIZED:",
          "})(k={TOKENIZED:",
          "}*{TOKENIZED:",
          "}*{TOKENIZED:",
          "}))"
        },
        new String[]
        {
          "(&(a={TOKENIZED:",
          "})(c>=d)(e<=f)(g~=h)(i:=j)(k=l*m*n))"
        },
        new String[]
        {
          "(&(a=b)(c>={TOKENIZED:",
          "})(e<={TOKENIZED:",
          "})(g~={TOKENIZED:",
          "})(i:={TOKENIZED:",
          "})(k={TOKENIZED:",
          "}*{TOKENIZED:",
          "}*{TOKENIZED:",
          "}))"
        }
      },

      // An OR filter.
      new Object[]
      {
        "(|(a=b)(c>=d)(e<=f)(g~=h)(i:=j)(k=l*m*n))",
        "(|(a=b)(c>=d)(e<=f)(g~=h)(i:=j)(k=l*m*n))",
        "(|(a={REDACTED})(c>={REDACTED})(e<={REDACTED})(g~={REDACTED})" +
             "(i:={REDACTED})(k={REDACTED}*{REDACTED}*{REDACTED}))",
        "(|(a={REDACTED})(c>=d)(e<=f)(g~=h)(i:=j)(k=l*m*n))",
        "(|(a=b)(c>={REDACTED})(e<={REDACTED})(g~={REDACTED})" +
             "(i:={REDACTED})(k={REDACTED}*{REDACTED}*{REDACTED}))",
        new String[]
        {
          "(|(a={TOKENIZED:",
          "})(c>={TOKENIZED:",
          "})(e<={TOKENIZED:",
          "})(g~={TOKENIZED:",
          "})(i:={TOKENIZED:",
          "})(k={TOKENIZED:",
          "}*{TOKENIZED:",
          "}*{TOKENIZED:",
          "}))"
        },
        new String[]
        {
          "(|(a={TOKENIZED:",
          "})(c>=d)(e<=f)(g~=h)(i:=j)(k=l*m*n))"
        },
        new String[]
        {
          "(|(a=b)(c>={TOKENIZED:",
          "})(e<={TOKENIZED:",
          "})(g~={TOKENIZED:",
          "})(i:={TOKENIZED:",
          "})(k={TOKENIZED:",
          "}*{TOKENIZED:",
          "}*{TOKENIZED:",
          "}))"
        }
      },

      // A NOT filter.
      new Object[]
      {
        "(!(a>=b))",
        "(!(a>=b))",
        "(!(a>={REDACTED}))",
        "(!(a>={REDACTED}))",
        "(!(a>=b))",
        new String[]
        {
          "(!(a>={TOKENIZED:",
          "}))"
        },
        new String[]
        {
          "(!(a>={TOKENIZED:",
          "}))"
        },
        new String[]
        {
          "(!(a>=b))"
        }
      },
    };
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
    final FilterLogFieldSyntax syntax = new FilterLogFieldSyntax(100, null,
         includedAttributes, excludedAttributes);

    final ByteStringBuffer buffer = new ByteStringBuffer();
    syntax.logSanitizedFieldToTextFormattedLog("abc",
         Filter.createEqualityFilter("uid", "test.user"),
         buffer);
    assertEquals(buffer.toString(),
         " abc=\"(uid=test.user)\"");

    buffer.clear();
    syntax.logCompletelyRedactedFieldToTextFormattedLog("def", buffer);
    assertEquals(buffer.toString(), " def=\"(redacted={REDACTED})\"");

    buffer.clear();
    syntax.logRedactedComponentsFieldToTextFormattedLog("ghi",
         Filter.createEqualityFilter("uid", "test.user"),
         buffer);
    assertEquals(buffer.toString(),
         " ghi=\"(uid={REDACTED})\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToTextFormattedLog("jkl",
         Filter.createEqualityFilter("uid", "test.user"),
         pepper, buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         " jkl=\"(tokenized={TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("})\""));

    buffer.clear();
    syntax.logTokenizedComponentsFieldToTextFormattedLog("mno",
         Filter.createEqualityFilter("uid", "test.user"),
         pepper, buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(" mno=\"(uid={TOKENIZED:"));
    assertTrue(tokenizedComponentsString.endsWith("})\""));
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
    final FilterLogFieldSyntax syntax = new FilterLogFieldSyntax(100, null,
         includedAttributes, excludedAttributes);

    final JSONBuffer buffer = new JSONBuffer();
    buffer.beginObject();
    syntax.logSanitizedFieldToJSONFormattedLog("abc",
         Filter.createEqualityFilter("uid", "test.user"),
         buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"abc\":\"(uid=test.user)\" }");

    buffer.clear();
    buffer.beginObject();
    syntax.logCompletelyRedactedFieldToJSONFormattedLog("def", buffer);
    buffer.endObject();
    assertEquals(buffer.toString(), "{ \"def\":\"(redacted={REDACTED})\" }");

    buffer.clear();
    buffer.beginObject();
    syntax.logRedactedComponentsFieldToJSONFormattedLog("ghi",
         Filter.createEqualityFilter("uid", "test.user"),
         buffer);
    buffer.endObject();
    assertEquals(buffer.toString(),
         "{ \"ghi\":\"(uid={REDACTED})\" }");

    buffer.clear();
    buffer.beginObject();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedFieldToJSONFormattedLog("jkl",
         Filter.createEqualityFilter("uid", "test.user"),
         pepper, buffer);
    buffer.endObject();
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         "{ \"jkl\":\"(tokenized={TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("})\" }"));

    buffer.clear();
    buffer.beginObject();
    syntax.logTokenizedComponentsFieldToJSONFormattedLog("mno",
         Filter.createEqualityFilter("uid", "test.user"),
         pepper, buffer);
    buffer.endObject();
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(
         "{ \"mno\":\"(uid={TOKENIZED:"));
    assertTrue(tokenizedComponentsString.endsWith("})\" }"));
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
    final FilterLogFieldSyntax syntax = new FilterLogFieldSyntax(100, null,
         includedAttributes, excludedAttributes);

    final JSONBuffer buffer = new JSONBuffer();
    syntax.logSanitizedValueToJSONFormattedLog(
         Filter.createEqualityFilter("uid", "test.user"),
         buffer);
    assertEquals(buffer.toString(),
         "\"(uid=test.user)\"");

    buffer.clear();
    syntax.logCompletelyRedactedValueToJSONFormattedLog(buffer);
    assertEquals(buffer.toString(), "\"(redacted={REDACTED})\"");

    buffer.clear();
    syntax.logRedactedComponentsValueToJSONFormattedLog(
         Filter.createEqualityFilter("uid", "test.user"),
         buffer);
    assertEquals(buffer.toString(),
         "\"(uid={REDACTED})\"");

    buffer.clear();
    final byte[] pepper = StaticUtils.randomBytes(8, false);
    syntax.logCompletelyTokenizedValueToJSONFormattedLog(
         Filter.createEqualityFilter("uid", "test.user"),
         pepper, buffer);
    final String completelyTokenizedString = buffer.toString();
    assertTrue(completelyTokenizedString.startsWith(
         "\"(tokenized={TOKENIZED:"));
    assertTrue(completelyTokenizedString.endsWith("})\""));

    buffer.clear();
    syntax.logTokenizedComponentsValueToJSONFormattedLog(
         Filter.createEqualityFilter("uid", "test.user"),
         pepper, buffer);
    final String tokenizedComponentsString = buffer.toString();
    assertTrue(tokenizedComponentsString.startsWith(
         "\"(uid={TOKENIZED:"));
    assertTrue(tokenizedComponentsString.endsWith("})\""));
  }
}
