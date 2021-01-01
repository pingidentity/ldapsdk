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



import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.StaticUtilsTestCase;



/**
 * This class provides a set of test cases for the GeneralizedTimeMatchingRule
 * class.
 */
public class GeneralizedTimeMatchingRuleTestCase
       extends MatchingRuleTestCase
{
  /**
   * Tests the {@code valuesMatch} method with a set of valid values.
   *
   * @param  value  The value to compare.
   * @param  date   The expected date.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidValues")
  public void testValuesMatch(String value, Date date)
         throws Exception
  {
    GeneralizedTimeMatchingRule mr =
         GeneralizedTimeMatchingRule.getInstance();

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

    assertTrue(mr.valuesMatch(new ASN1OctetString(value),
                              new ASN1OctetString(dateFormat.format(date))));

    assertFalse(mr.valuesMatch(new ASN1OctetString(value),
         new ASN1OctetString(dateFormat.format(new Date()))));
  }



  /**
   * Tests the {@code valuesMatch} method with an invalid value.
   *
   * @param  invalidValue  The invalid value to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testInvalidValues")
  public void testValuesMatchInvalid(String invalidValue)
         throws Exception
  {
    GeneralizedTimeMatchingRule mr =
         GeneralizedTimeMatchingRule.getInstance();

    try
    {
      mr.valuesMatch(new ASN1OctetString(invalidValue),
                     new ASN1OctetString("20080101000000Z"));
      fail("Expected an exception with an invalid first value.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      mr.valuesMatch(new ASN1OctetString("20080101000000Z"),
                     new ASN1OctetString(invalidValue));
      fail("Expected an exception with an invalid second value.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests to ensure that the {@code matchesSubstring} method will always throw
   * an exception.
   *
   * @param  value  The value to compare.
   * @param  date   The date for the provided timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidValues",
        expectedExceptions = { LDAPException.class })
  public void testMatchesSubstring(String value, Date date)
         throws Exception
  {
    GeneralizedTimeMatchingRule mr =
         GeneralizedTimeMatchingRule.getInstance();

    mr.matchesSubstring(new ASN1OctetString(value),
                        new ASN1OctetString(value), null, null);
  }



  /**
   * Tests to ensure that the {@code compareValues} method behaves as expected
   * when given valid values.
   *
   * @param  value  The value to compare.
   * @param  date   The expected date.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidValues")
  public void testCompareValuesValid(String value, Date date)
         throws Exception
  {
    GeneralizedTimeMatchingRule mr =
         GeneralizedTimeMatchingRule.getInstance();

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

    assertEquals(mr.compareValues(new ASN1OctetString(value),
                      new ASN1OctetString(dateFormat.format(date))),
                 0);

    Date d2 = new Date(date.getTime() - (2*86400000L));
    assertTrue(mr.compareValues(new ASN1OctetString(value),
                    new ASN1OctetString(dateFormat.format(d2))) > 0);

    d2 = new Date(date.getTime() + (2*86400000L));
    assertTrue(mr.compareValues(new ASN1OctetString(value),
                    new ASN1OctetString(dateFormat.format(d2))) < 0);
  }



  /**
   * Tests to ensure that the {@code compareValues} method behaves as expected
   * when given invalid values.
   *
   * @param  invalidValue  The invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testInvalidValues")
  public void testCompareValuesInvalid(String invalidValue)
         throws Exception
  {
    GeneralizedTimeMatchingRule mr =
         GeneralizedTimeMatchingRule.getInstance();

    try
    {
      mr.compareValues(new ASN1OctetString(invalidValue),
                       new ASN1OctetString("20080101000000Z"));
      fail("Expected an exception with an invalid first value.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      mr.compareValues(new ASN1OctetString("20080101000000Z"),
                       new ASN1OctetString(invalidValue));
      fail("Expected an exception with an invalid second value.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests to ensure that the {@code normalize} method returns the appropriate
   * value when given valid values.
   *
   * @param  value  The value to compare.
   * @param  date   The expected date.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidValues")
  public void testNormalizeValid(String value, Date date)
         throws Exception
  {
    GeneralizedTimeMatchingRule mr =
         GeneralizedTimeMatchingRule.getInstance();

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

    assertEquals(mr.normalize(new ASN1OctetString(value)),
                 new ASN1OctetString(dateFormat.format(date)));
  }



  /**
   * Tests to ensure that the {@code normalize} method throws an exception when
   * given values that aren't valid timestamps.
   *
   * @param  invalidValue  A string that cannot be parsed as a valid timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testInvalidValues",
        expectedExceptions = { LDAPException.class })
  public void testNormalizeInvalid(String invalidValue)
         throws Exception
  {
    GeneralizedTimeMatchingRule mr =
         GeneralizedTimeMatchingRule.getInstance();

    mr.normalize(new ASN1OctetString(invalidValue));
  }



  /**
   * Tests to ensure that the {@code normalizeSubstring} method always throws an
   * exception.
   *
   * @param  value  The value to compare.
   * @param  date   The expected date.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidValues",
        expectedExceptions = { LDAPException.class })
  public void testNormalizeSubstring(String value, Date date)
         throws Exception
  {
    GeneralizedTimeMatchingRule mr =
         GeneralizedTimeMatchingRule.getInstance();

    mr.normalizeSubstring(new ASN1OctetString(value), (byte) 0x80);
  }



  /**
   * Retrieves a set of strings that may be used to create valid timestamps.
   *
   * @return  A set of strings that may be used to create valid timestamps.
   */
  @DataProvider(name = "testValidValues")
  public Object[][] getTestValidDValues()
  {
    return new StaticUtilsTestCase().getValidGeneralizedTimestamps();
  }



  /**
   * Retrieves a set of strings that cannot be used to create valid timestamps.
   *
   * @return  A set of strings that cannot be used to create valid timestamps.
   */
  @DataProvider(name = "testInvalidValues")
  public Object[][] getTestInvalidValues()
  {
    return new StaticUtilsTestCase().getInvalidGeneralizedTimestamps();
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
    GeneralizedTimeMatchingRule mr = GeneralizedTimeMatchingRule.getInstance();

    assertNotNull(mr.getEqualityMatchingRuleName());
    assertEquals(mr.getEqualityMatchingRuleName(), "generalizedTimeMatch");

    assertNotNull(mr.getEqualityMatchingRuleOID());
    assertEquals(mr.getEqualityMatchingRuleOID(), "2.5.13.27");

    assertNotNull(mr.getEqualityMatchingRuleNameOrOID());
    assertEquals(mr.getEqualityMatchingRuleNameOrOID(), "generalizedTimeMatch");

    assertNotNull(mr.getOrderingMatchingRuleName());
    assertEquals(mr.getOrderingMatchingRuleName(),
         "generalizedTimeOrderingMatch");

    assertNotNull(mr.getOrderingMatchingRuleOID());
    assertEquals(mr.getOrderingMatchingRuleOID(), "2.5.13.28");

    assertNotNull(mr.getOrderingMatchingRuleNameOrOID());
    assertEquals(mr.getOrderingMatchingRuleNameOrOID(),
         "generalizedTimeOrderingMatch");

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
    final GeneralizedTimeMatchingRule mr =
         GeneralizedTimeMatchingRule.getInstance();

    final ASN1OctetString assertionValue =
         new ASN1OctetString("20170102030405.678Z");
    assertFalse(mr.matchesAnyValue(assertionValue, null));
    assertFalse(mr.matchesAnyValue(assertionValue, new ASN1OctetString[0]));

    final ASN1OctetString[] attributeValues =
    {
      new ASN1OctetString("20160102030405.678Z"),
      new ASN1OctetString("not a valid generalized time"),
      new ASN1OctetString("20170102030405.678Z"),
      new ASN1OctetString("20180102030405.678Z")
    };

    assertFalse(mr.matchesAnyValue(null, attributeValues));

    assertTrue(mr.matchesAnyValue(assertionValue, attributeValues));
    assertTrue(mr.matchesAnyValue(new ASN1OctetString("20160102030405.678Z"),
         attributeValues));
    assertTrue(mr.matchesAnyValue(
         new ASN1OctetString("20180102030405.678Z"), attributeValues));

    assertFalse(mr.matchesAnyValue(new ASN1OctetString("20150102030405.678Z"),
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
