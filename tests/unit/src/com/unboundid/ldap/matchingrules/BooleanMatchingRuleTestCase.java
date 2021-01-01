/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;



/**
 * This class provides a set of test cases for the BooleanMatchingRule class.
 */
public class BooleanMatchingRuleTestCase
       extends MatchingRuleTestCase
{
  /**
   * Performs a number of tests with values that should resolve to "TRUE".
   *
   * @param  value  The value to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="trueValues")
  public void testTrueValues(String value)
         throws Exception
  {
    BooleanMatchingRule mr = BooleanMatchingRule.getInstance();

    assertTrue(mr.valuesMatch(new ASN1OctetString(value),
                              new ASN1OctetString("TRUE")));

    assertEquals(mr.normalize(new ASN1OctetString(value)),
                 new ASN1OctetString("TRUE"));
  }



  /**
   * Performs a number of tests with values that should resolve to "FALSE".
   *
   * @param  value  The value to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="falseValues")
  public void testFalseValues(String value)
         throws Exception
  {
    BooleanMatchingRule mr = BooleanMatchingRule.getInstance();

    assertTrue(mr.valuesMatch(new ASN1OctetString(value),
                              new ASN1OctetString("FALSE")));

    assertEquals(mr.normalize(new ASN1OctetString(value)),
                 new ASN1OctetString("FALSE"));
  }



  /**
   * Performs a number of tests with invalid values.
   *
   * @param  value  The value to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="invalidValues",
        expectedExceptions = { LDAPException.class })
  public void testInvalidValues(String value)
         throws Exception
  {
    BooleanMatchingRule mr = BooleanMatchingRule.getInstance();

    mr.normalize(new ASN1OctetString(value));
  }



  /**
   * Ensures that attempts to perform substring matching will fail.
   *
   * @param  value  The value to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="trueValues",
        expectedExceptions = { LDAPException.class })
  public void testMatchesSubstring(String value)
         throws Exception
  {
    BooleanMatchingRule mr = BooleanMatchingRule.getInstance();

    mr.matchesSubstring(new ASN1OctetString(value),
                        new ASN1OctetString(value), null, null);
  }



  /**
   * Ensures that attempts to perform ordering matching will fail.
   *
   * @param  value  The value to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="trueValues",
        expectedExceptions = { LDAPException.class })
  public void testCompareValues(String value)
         throws Exception
  {
    BooleanMatchingRule mr = BooleanMatchingRule.getInstance();

    mr.compareValues(new ASN1OctetString(value), new ASN1OctetString(value));
  }



  /**
   * Ensures that attempts to perform substring normalization will fail.
   *
   * @param  value  The value to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="trueValues",
        expectedExceptions = { LDAPException.class })
  public void testNormalizeSubstring(String value)
         throws Exception
  {
    BooleanMatchingRule mr = BooleanMatchingRule.getInstance();

    mr.normalizeSubstring(new ASN1OctetString(value), (byte) 0x80);
  }



  /**
   * Retrieves a set of string values that should resolve to "TRUE".
   *
   * @return  A set of string values that should resolve to "TRUE".
   */
  @DataProvider(name="trueValues")
  public Object[][] getTrueValues()
  {
    return new Object[][]
    {
      new Object[] { "true" },
      new Object[] { "True" },
      new Object[] { "tRue" },
      new Object[] { "trUe" },
      new Object[] { "truE" },
      new Object[] { "TRue" },
      new Object[] { "TrUe" },
      new Object[] { "TruE" },
      new Object[] { "tRUe" },
      new Object[] { "tRuE" },
      new Object[] { "trUE" },
      new Object[] { "tRUE" },
      new Object[] { "TrUE" },
      new Object[] { "TRuE" },
      new Object[] { "TRUe" },
      new Object[] { "TRUE" }
    };
  }



  /**
   * Retrieves a set of string values that should resolve to "FALSE".
   *
   * @return  A set of string values that should resolve to "FALSE".
   */
  @DataProvider(name="falseValues")
  public Object[][] getFalseValues()
  {
    return new Object[][]
    {
      new Object[] { "false" },
      new Object[] { "False" },
      new Object[] { "fAlse" },
      new Object[] { "faLse" },
      new Object[] { "falSe" },
      new Object[] { "falsE" },
      new Object[] { "FAlse" },
      new Object[] { "FaLse" },
      new Object[] { "FalSe" },
      new Object[] { "FalsE" },
      new Object[] { "fALse" },
      new Object[] { "fAlSe" },
      new Object[] { "fAlsE" },
      new Object[] { "faLSe" },
      new Object[] { "faLsE" },
      new Object[] { "falSE" },
      new Object[] { "FALse" },
      new Object[] { "FAlSe" },
      new Object[] { "FAlsE" },
      new Object[] { "FaLSe" },
      new Object[] { "FaLsE" },
      new Object[] { "FalSE" },
      new Object[] { "fALSe" },
      new Object[] { "fALsE" },
      new Object[] { "fAlSE" },
      new Object[] { "faLSE" },
      new Object[] { "fALSE" },
      new Object[] { "FaLSE" },
      new Object[] { "FAlSE" },
      new Object[] { "FALsE" },
      new Object[] { "FALSe" },
      new Object[] { "FALSE" },
    };
  }



  /**
   * Retrieves a set of strings that do not represent valid Boolean values.
   *
   * @return  A set of strings that do not represent valid Boolean values.
   */
  @DataProvider(name="invalidValues")
  public Object[][] getInvalidValues()
  {
    return new Object[][]
    {
      new Object[] { "" },
      new Object[] { "t" },
      new Object[] { "f" },
      new Object[] { "y" },
      new Object[] { "n" },
      new Object[] { "yes" },
      new Object[] { "no" },
      new Object[] { "1" },
      new Object[] { "0" },
      new Object[] { " true" },
      new Object[] { " false" },
      new Object[] { "true " },
      new Object[] { "false " },
      new Object[] { "invalid" },
    };
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
    BooleanMatchingRule mr = BooleanMatchingRule.getInstance();

    assertNotNull(mr.getEqualityMatchingRuleName());
    assertEquals(mr.getEqualityMatchingRuleName(), "booleanMatch");

    assertNotNull(mr.getEqualityMatchingRuleOID());
    assertEquals(mr.getEqualityMatchingRuleOID(), "2.5.13.13");

    assertNotNull(mr.getEqualityMatchingRuleNameOrOID());
    assertEquals(mr.getEqualityMatchingRuleNameOrOID(), "booleanMatch");

    assertNull(mr.getOrderingMatchingRuleName());

    assertNull(mr.getOrderingMatchingRuleOID());

    assertNull(mr.getOrderingMatchingRuleNameOrOID());

    assertNull(mr.getSubstringMatchingRuleName());

    assertNull(mr.getSubstringMatchingRuleOID());

    assertNull(mr.getSubstringMatchingRuleNameOrOID());
  }



  /**
   * Provides test coverage for the {@code matchesAnyValue} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchesAnyValue()
         throws Exception
  {
    final BooleanMatchingRule mr = BooleanMatchingRule.getInstance();

    final ASN1OctetString assertionValue =
         new ASN1OctetString("TRUE");
    assertFalse(mr.matchesAnyValue(assertionValue, null));
    assertFalse(mr.matchesAnyValue(assertionValue, new ASN1OctetString[0]));

    final ASN1OctetString[] attributeValues =
    {
      new ASN1OctetString("not a valid Boolean"),
      new ASN1OctetString("TRUE"),
    };


    assertFalse(mr.matchesAnyValue(null, attributeValues));

    assertTrue(mr.matchesAnyValue(assertionValue, attributeValues));
    assertTrue(mr.matchesAnyValue(new ASN1OctetString("true"),
         attributeValues));
    assertTrue(mr.matchesAnyValue(new ASN1OctetString("True"),
         attributeValues));

    assertFalse(mr.matchesAnyValue(new ASN1OctetString("FALSE"),
         attributeValues));

    try
    {
      mr.matchesAnyValue(new ASN1OctetString("malformed"), attributeValues);
      fail("Expected an LDAP exception when providing a malformed assertion " +
           "value");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }
}
