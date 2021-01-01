/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.matchingrules;



import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the {@code CaseIgnoreListMatchingRule}
 * class.
 */
public class CaseIgnoreListMatchingRuleTestCase
       extends MatchingRuleTestCase
{
  /**
   * Performs a set of tests with a list with no items.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoItems()
         throws Exception
  {
    CaseIgnoreListMatchingRule mr = CaseIgnoreListMatchingRule.getInstance();

    try
    {
      mr.valuesMatch(new ASN1OctetString("foo"), new ASN1OctetString(""));
      fail("Expected an exception from valuesMatch");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      mr.matchesSubstring(new ASN1OctetString(""), new ASN1OctetString("foo"),
           null, null);
      fail("Expected an exception from matchesSubstring");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      CaseIgnoreListMatchingRule.getItems(new ASN1OctetString(""));
      fail("Expected an exception from getItems with an octet string");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      CaseIgnoreListMatchingRule.getItems("");
      fail("Expected an exception from getItems with a string");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      CaseIgnoreListMatchingRule.getLowercaseItems(new ASN1OctetString(""));
      fail("Expected an exception from getLowercaseItems with an octet string");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      CaseIgnoreListMatchingRule.getLowercaseItems("");
      fail("Expected an exception from getLowercaseItems with a string");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Performs a set of tests with a list with a single item.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleItem()
         throws Exception
  {
    CaseIgnoreListMatchingRule mr = CaseIgnoreListMatchingRule.getInstance();

    ASN1OctetString normValue = new ASN1OctetString("foo");
    assertEquals(mr.normalize(new ASN1OctetString("foo")), normValue);
    assertEquals(mr.normalize(new ASN1OctetString("Foo")), normValue);
    assertEquals(mr.normalize(new ASN1OctetString("FOO")), normValue);
    assertEquals(mr.normalize(new ASN1OctetString(" foo ")), normValue);
    assertEquals(mr.normalize(new ASN1OctetString(" fOo ")), normValue);

    assertTrue(mr.valuesMatch(new ASN1OctetString("foo"), normValue));
    assertTrue(mr.valuesMatch(new ASN1OctetString("Foo"), normValue));
    assertTrue(mr.valuesMatch(new ASN1OctetString("FOO"), normValue));
    assertTrue(mr.valuesMatch(new ASN1OctetString(" foo "), normValue));
    assertTrue(mr.valuesMatch(new ASN1OctetString(" fOo "), normValue));
    assertTrue(mr.valuesMatch(new ASN1OctetString(" fOo "), normValue));

    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo"),
         new ASN1OctetString("f"), null, null));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo"),
         new ASN1OctetString("F"), null, null));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo"),
         new ASN1OctetString("foo"), null, null));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo"),
         new ASN1OctetString("FOO"), null, null));
    assertFalse(mr.matchesSubstring(new ASN1OctetString("foo"),
         new ASN1OctetString("oo"), null, null));

    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo"), null, null,
         new ASN1OctetString("o")));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo"), null, null,
         new ASN1OctetString("O")));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo"), null, null,
         new ASN1OctetString("foo")));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo"), null, null,
         new ASN1OctetString("FOO")));
    assertFalse(mr.matchesSubstring(new ASN1OctetString("foo"), null, null,
         new ASN1OctetString("f")));
    assertFalse(mr.matchesSubstring(new ASN1OctetString("foo"), null, null,
         new ASN1OctetString("fo")));

    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo"), null,
         new ASN1OctetString[] { new ASN1OctetString("foo") }, null));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo"), null,
         new ASN1OctetString[] { new ASN1OctetString("FOO") }, null));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo"),
         new ASN1OctetString("f"),
         new ASN1OctetString[] { new ASN1OctetString("o") },
         new ASN1OctetString("o")));
    assertFalse(mr.matchesSubstring(new ASN1OctetString("foo"),
         new ASN1OctetString("f"),
         new ASN1OctetString[] { new ASN1OctetString("oo") },
         new ASN1OctetString("o")));

    List<String> items = CaseIgnoreListMatchingRule.getItems(
         new ASN1OctetString("Foo"));
    assertNotNull(items);
    assertEquals(items.size(), 1);
    assertEquals(items.get(0), "Foo");

    items = CaseIgnoreListMatchingRule.getLowercaseItems(
         new ASN1OctetString("Foo"));
    assertNotNull(items);
    assertEquals(items.size(), 1);
    assertEquals(items.get(0), "foo");
  }



  /**
   * Performs a set of tests with a list with multiple items.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleItems()
         throws Exception
  {
    CaseIgnoreListMatchingRule mr = CaseIgnoreListMatchingRule.getInstance();

    ASN1OctetString normValue = new ASN1OctetString("foo$bar$baz");
    assertEquals(mr.normalize(new ASN1OctetString("foo$bar$baz")), normValue);
    assertEquals(mr.normalize(new ASN1OctetString("Foo $ bAr $ baZ")),
         normValue);

    assertTrue(mr.valuesMatch(new ASN1OctetString("foo$bar$baz"), normValue));
    assertTrue(mr.valuesMatch(new ASN1OctetString("Foo $ bAr $ baZ"),
         normValue));

    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"),
         new ASN1OctetString("foo"), null, null));
    assertFalse(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"),
         new ASN1OctetString("bar"), null, null));
    assertFalse(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"),
         new ASN1OctetString("baz"), null, null));

    assertFalse(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"), null,
         null, new ASN1OctetString("foo")));
    assertFalse(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"), null,
         null, new ASN1OctetString("bar")));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"), null,
         null, new ASN1OctetString("baz")));

    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"), null,
         new ASN1OctetString[] { new ASN1OctetString("foo") }, null));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"), null,
         new ASN1OctetString[] { new ASN1OctetString("bar") }, null));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"), null,
         new ASN1OctetString[] { new ASN1OctetString("baz") }, null));
    assertFalse(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"), null,
         new ASN1OctetString[] { new ASN1OctetString("ooba") }, null));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"), null,
         new ASN1OctetString[] { new ASN1OctetString("foo"),
                                 new ASN1OctetString("bar"),
                                 new ASN1OctetString("baz") },
         null));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"),
         new ASN1OctetString("foo"),
         new ASN1OctetString[] { new ASN1OctetString("bar") },
         new ASN1OctetString("baz")));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"),
         new ASN1OctetString("foo"),
         new ASN1OctetString[] { new ASN1OctetString("baz") },
         null));
    assertTrue(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"),
         null,
         new ASN1OctetString[] { new ASN1OctetString("foo") },
         new ASN1OctetString("baz")));
    assertFalse(mr.matchesSubstring(new ASN1OctetString("foo$bar$baz"),
         new ASN1OctetString("foo"),
         new ASN1OctetString[] { new ASN1OctetString("foo") },
         null));

    List<String> items = CaseIgnoreListMatchingRule.getItems(
         new ASN1OctetString("Foo $ bAr $ baZ"));
    assertNotNull(items);
    assertEquals(items.size(), 3);
    assertEquals(items.get(0), "Foo");
    assertEquals(items.get(1), "bAr");
    assertEquals(items.get(2), "baZ");

    items = CaseIgnoreListMatchingRule.getLowercaseItems(
         new ASN1OctetString("Foo $ bAr $ baZ"));
    assertNotNull(items);
    assertEquals(items.size(), 3);
    assertEquals(items.get(0), "foo");
    assertEquals(items.get(1), "bar");
    assertEquals(items.get(2), "baz");
  }



  /**
   * Performs a set of tests with empty list items.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyListItems()
         throws Exception
  {
    CaseIgnoreListMatchingRule mr = CaseIgnoreListMatchingRule.getInstance();

    try
    {
      mr.normalize(new ASN1OctetString("$foo$bar"));
      fail("Expected an exception with an empty first item");
    }
    catch (Exception e)
    {
      // This was expected.
    }

    try
    {
      mr.normalize(new ASN1OctetString("foo$$bar"));
      fail("Expected an exception with an empty middle item");
    }
    catch (Exception e)
    {
      // This was expected.
    }

    try
    {
      mr.normalize(new ASN1OctetString("foo$bar$"));
      fail("Expected an exception with an empty last item");
    }
    catch (Exception e)
    {
      // This was expected.
    }
  }



  /**
   * Performs a set of tests with values containing spaces.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValuesWithSpaces()
         throws Exception
  {
    CaseIgnoreListMatchingRule mr = CaseIgnoreListMatchingRule.getInstance();

    assertEquals(mr.normalize(new ASN1OctetString("a b$ c  d  $   e   f")),
                 new ASN1OctetString("a b$c d$e f"));
  }



  /**
   * Provides test coverage for the case in which the list contains valid
   * escaped values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidEscapedValues()
         throws Exception
  {
    CaseIgnoreListMatchingRule mr = CaseIgnoreListMatchingRule.getInstance();

    ASN1OctetString value = new ASN1OctetString("\\24a$b\\5c");

    assertEquals(mr.normalize(new ASN1OctetString("\\24A $ B\\5C")), value);

    assertTrue(mr.valuesMatch(new ASN1OctetString("\\24A $ B\\5C"), value));

    assertTrue(mr.matchesSubstring(value, new ASN1OctetString("\\24A"), null,
         null));
    assertTrue(mr.matchesSubstring(value, null,
         new ASN1OctetString[] { new ASN1OctetString("\\24A") },
         null));
    assertTrue(mr.matchesSubstring(value, null,
         new ASN1OctetString[] { new ASN1OctetString("B\\5C") },
         null));
    assertTrue(mr.matchesSubstring(value, null,
         new ASN1OctetString[] { new ASN1OctetString("\\24A"),
                                 new ASN1OctetString("B\\5C") },
         null));
    assertFalse(mr.matchesSubstring(value, null,
         new ASN1OctetString[] { new ASN1OctetString("B\\5C"),
                                 new ASN1OctetString("\\24A") },
         null));

    List<String> items = CaseIgnoreListMatchingRule.getItems(value);
    assertNotNull(items);
    assertEquals(items.size(), 2);
    assertEquals(items.get(0), "$a");
    assertEquals(items.get(1), "b\\");

    items = CaseIgnoreListMatchingRule.getLowercaseItems(value);
    assertNotNull(items);
    assertEquals(items.size(), 2);
    assertEquals(items.get(0), "$a");
    assertEquals(items.get(1), "b\\");
  }



  /**
   * Provides test coverage for the case in which the list contains invalid
   * escaped values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidEscapedValues()
         throws Exception
  {
    CaseIgnoreListMatchingRule mr = CaseIgnoreListMatchingRule.getInstance();

    try
    {
      mr.normalize(new ASN1OctetString("a\\b"));
      fail("Expected an exception from a hex value that is too short");
    }
    catch (LDAPException le)
    {
      // This was expected
    }

    try
    {
      mr.normalize(new ASN1OctetString("a\\x1"));
      fail("Expected an exception from an invalid first hex digit");
    }
    catch (LDAPException le)
    {
      // This was expected
    }

    try
    {
      mr.normalize(new ASN1OctetString("a\\1x"));
      fail("Expected an exception from an invalid second hex digit");
    }
    catch (LDAPException le)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the {@code compareValues} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCompareValues()
         throws Exception
  {
    CaseIgnoreListMatchingRule mr = CaseIgnoreListMatchingRule.getInstance();

    mr.compareValues(new ASN1OctetString("foo"), new ASN1OctetString("bar"));
  }



  /**
   * Verify the correct behavior for substring assertions containing dollar
   * signs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidSubstrings()
         throws Exception
  {
    CaseIgnoreListMatchingRule mr = CaseIgnoreListMatchingRule.getInstance();
    ASN1OctetString value = new ASN1OctetString("foo$bar$baz");

    try
    {
      mr.matchesSubstring(value, new ASN1OctetString("foo$bar"), null, null);
      fail("Expected an exception for an invalid subInitial");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      mr.matchesSubstring(value, null,
           new ASN1OctetString[] { new ASN1OctetString("foo$bar") }, null);
      fail("Expected an exception for an invalid subAny");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      mr.matchesSubstring(value, null, null, new ASN1OctetString("foo$bar"));
      fail("Expected an exception for an invalid subFinal");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code decodeHexChar} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeHexChar()
         throws Exception
  {
    for (int i=0; i <= 255; i++)
    {
      byte b = (byte) (i & 0xFF);

      String hexStr = toLowerCase(toHex(b));
      char c = CaseIgnoreListMatchingRule.decodeHexChar(hexStr, 0);
      assertEquals(((int) c), i);

      hexStr = hexStr.toUpperCase();
      c = CaseIgnoreListMatchingRule.decodeHexChar(hexStr, 0);
      assertEquals(((int) c), i);
    }
  }



  /**
   * Provides test coverage for the methods used to retrieve the names and OIDs
   * for the matching rules.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNamesAndOIDs()
         throws Exception
  {
    CaseIgnoreListMatchingRule mr = CaseIgnoreListMatchingRule.getInstance();

    assertNotNull(mr.getEqualityMatchingRuleName());
    assertEquals(mr.getEqualityMatchingRuleName(), "caseIgnoreListMatch");

    assertNotNull(mr.getEqualityMatchingRuleOID());
    assertEquals(mr.getEqualityMatchingRuleOID(), "2.5.13.11");

    assertNotNull(mr.getEqualityMatchingRuleNameOrOID());
    assertEquals(mr.getEqualityMatchingRuleNameOrOID(), "caseIgnoreListMatch");

    assertNull(mr.getOrderingMatchingRuleName());

    assertNull(mr.getOrderingMatchingRuleOID());

    assertNull(mr.getOrderingMatchingRuleNameOrOID());

    assertNotNull(mr.getSubstringMatchingRuleName());
    assertEquals(mr.getSubstringMatchingRuleName(),
         "caseIgnoreListSubstringsMatch");

    assertNotNull(mr.getSubstringMatchingRuleOID());
    assertEquals(mr.getSubstringMatchingRuleOID(), "2.5.13.12");

    assertNotNull(mr.getSubstringMatchingRuleNameOrOID());
    assertEquals(mr.getSubstringMatchingRuleNameOrOID(),
         "caseIgnoreListSubstringsMatch");
  }
}
