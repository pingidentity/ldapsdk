/*
 * Copyright 2008-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 Ping Identity Corporation
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



import java.math.BigInteger;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;



/**
 * This class provides a set of test cases for the IntegerMatchingRule class.
 */
public class IntegerMatchingRuleTestCase
       extends MatchingRuleTestCase
{
  /**
   * Tests the {@code valuesMatch} method with valid values.
   *
   * @param  valueStr  The string representation of the value.
   * @param  bigInt    The parsed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validValues")
  public void testValuesMatch(String valueStr, BigInteger bigInt)
         throws Exception
  {
    IntegerMatchingRule mr = IntegerMatchingRule.getInstance();

    assertTrue(mr.valuesMatch(new ASN1OctetString(valueStr),
                              new ASN1OctetString(bigInt.toString())),
               valueStr + ", " + bigInt.toString());
  }



  /**
   * Tests the {@code matchesSubstring} method to ensure that it throws an
   * exception.
   *
   * @param  valueStr  The string representation of the value.
   * @param  bigInt    The parsed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validValues",
        expectedExceptions = { LDAPException.class })
  public void testMatchesSubstring(String valueStr, BigInteger bigInt)
         throws Exception
  {
    IntegerMatchingRule mr = IntegerMatchingRule.getInstance();

    mr.matchesSubstring(new ASN1OctetString(valueStr),
                        new ASN1OctetString(valueStr), null, null);
  }



  /**
   * Tests the {@code compareValues} method with valid values.
   *
   * @param  valueStr  The string representation of the value.
   * @param  bigInt    The parsed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validValues")
  public void testCompareValues(String valueStr, BigInteger bigInt)
         throws Exception
  {
    IntegerMatchingRule mr = IntegerMatchingRule.getInstance();

    assertEquals(mr.compareValues(new ASN1OctetString(valueStr),
                                  new ASN1OctetString(bigInt.toString())),
                 0);

    BigInteger value2 = bigInt.add(
         BigInteger.valueOf(500L).multiply(BigInteger.valueOf(Long.MAX_VALUE)));
    assertTrue(mr.compareValues(new ASN1OctetString(valueStr),
                                new ASN1OctetString(value2.toString())) < 0);

    value2 = bigInt.add(BigInteger.valueOf(5L));
    assertTrue(mr.compareValues(new ASN1OctetString(valueStr),
                                new ASN1OctetString(value2.toString())) < 0);

    assertTrue(mr.compareValues(new ASN1OctetString(valueStr),
         new ASN1OctetString("123456789012345678901234567890")) < 0);

    value2 = bigInt.subtract(
         BigInteger.valueOf(500L).multiply(BigInteger.valueOf(Long.MAX_VALUE)));
    assertTrue(mr.compareValues(new ASN1OctetString(valueStr),
                                new ASN1OctetString(value2.toString())) > 0);

    value2 = bigInt.subtract(BigInteger.valueOf(5L));
    assertTrue(mr.compareValues(new ASN1OctetString(valueStr),
                                new ASN1OctetString(value2.toString())) > 0);

    assertTrue(mr.compareValues(new ASN1OctetString(valueStr),
         new ASN1OctetString("-123456789012345678901234567890")) > 0);

    value2 = bigInt.add(
         BigInteger.valueOf(500L).multiply(BigInteger.valueOf(Long.MAX_VALUE)));
    assertTrue(mr.compareValues(new ASN1OctetString(value2.toString()),
                                new ASN1OctetString(valueStr)) > 0);

    value2 = bigInt.add(BigInteger.valueOf(5L));
    assertTrue(mr.compareValues(new ASN1OctetString(value2.toString()),
                                new ASN1OctetString(valueStr)) > 0);

    assertTrue(mr.compareValues(
         new ASN1OctetString("123456789012345678901234567890"),
         new ASN1OctetString(valueStr)) > 0);

    value2 = bigInt.subtract(
         BigInteger.valueOf(500L).multiply(BigInteger.valueOf(Long.MAX_VALUE)));
    assertTrue(mr.compareValues(new ASN1OctetString(value2.toString()),
                                new ASN1OctetString(valueStr)) < 0);

    value2 = bigInt.subtract(BigInteger.valueOf(5L));
    assertTrue(mr.compareValues(new ASN1OctetString(value2.toString()),
                                new ASN1OctetString(valueStr)) < 0);

    assertTrue(mr.compareValues(
         new ASN1OctetString("-123456789012345678901234567890"),
         new ASN1OctetString(valueStr)) < 0);
  }



  /**
   * Tests to ensure that the normalize method will properly handle valid
   * values.
   *
   * @param  valueStr  The string representation of the value.
   * @param  bigInt    The parsed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validValues")
  public void testNormalizeValid(String valueStr, BigInteger bigInt)
         throws Exception
  {
    IntegerMatchingRule mr = IntegerMatchingRule.getInstance();

    assertEquals(mr.normalize(new ASN1OctetString(valueStr)),
                 new ASN1OctetString(valueStr.trim()));
  }



  /**
   * Tests to ensure that the normalize method will properly reject invalid
   * values.
   *
   * @param  invalidValue  The invalid value to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="invalidValues",
        expectedExceptions = { LDAPException.class })
  public void testNormalizeInvalid(String invalidValue)
         throws Exception
  {
    IntegerMatchingRule mr = IntegerMatchingRule.getInstance();

    mr.normalize(new ASN1OctetString(invalidValue));
  }



  /**
   * Tests to ensure that the normalizeSubstring method will always throw an
   * exception.
   *
   * @param  valueStr  The string representation of the value.
   * @param  bigInt    The parsed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validValues",
        expectedExceptions = { LDAPException.class })
  public void testNormalizeSubstring(String valueStr, BigInteger bigInt)
         throws Exception
  {
    IntegerMatchingRule mr = IntegerMatchingRule.getInstance();

    mr.normalizeSubstring(new ASN1OctetString(valueStr), (byte) 0x80);
  }



  /**
   * Provides a set of valid test data.
   *
   * @return  A set of valid test data.
   */
  @DataProvider(name="validValues")
  public Object[][] getValidValues()
  {
    return new Object[][]
    {
      new Object[] { "0", BigInteger.valueOf(0L) },
      new Object[] { "1", BigInteger.valueOf(1L) },
      new Object[] { "12345", BigInteger.valueOf(12345L) },
      new Object[] { String.valueOf(Integer.MAX_VALUE),
                     BigInteger.valueOf(Integer.MAX_VALUE) },
      new Object[] { String.valueOf(Long.MAX_VALUE),
                     BigInteger.valueOf(Long.MAX_VALUE) },
      new Object[] { String.valueOf(Long.MAX_VALUE) + "00",
                     BigInteger.valueOf(Long.MAX_VALUE).multiply(
                          BigInteger.valueOf(100L)) },
      new Object[] { "-1", BigInteger.valueOf(-1L) },
      new Object[] { "-12345", BigInteger.valueOf(-12345L) },
      new Object[] { String.valueOf(Integer.MIN_VALUE),
                     BigInteger.valueOf(Integer.MIN_VALUE) },
      new Object[] { String.valueOf(Long.MIN_VALUE),
                     BigInteger.valueOf(Long.MIN_VALUE) },
      new Object[] { '-' + String.valueOf(Long.MAX_VALUE) + "00",
                     BigInteger.valueOf(Long.MAX_VALUE).multiply(
                          BigInteger.valueOf(-100L)) },
      new Object[] { " 0 ", BigInteger.valueOf(0L) },
      new Object[] { " 1 ", BigInteger.valueOf(1L) },
      new Object[] { " 12345 ", BigInteger.valueOf(12345L) },
      new Object[] { ' ' + String.valueOf(Integer.MAX_VALUE) + ' ',
                     BigInteger.valueOf(Integer.MAX_VALUE) },
      new Object[] { ' ' + String.valueOf(Long.MAX_VALUE) + ' ',
                     BigInteger.valueOf(Long.MAX_VALUE) },
      new Object[] { ' ' + String.valueOf(Long.MAX_VALUE) + "00 ",
                     BigInteger.valueOf(Long.MAX_VALUE).multiply(
                          BigInteger.valueOf(100L)) },
      new Object[] { " -1 ", BigInteger.valueOf(-1L) },
      new Object[] { " -12345 ", BigInteger.valueOf(-12345L) },
      new Object[] { ' ' + String.valueOf(Integer.MIN_VALUE) + ' ',
                     BigInteger.valueOf(Integer.MIN_VALUE) },
      new Object[] { ' ' + String.valueOf(Long.MIN_VALUE) + ' ',
                     BigInteger.valueOf(Long.MIN_VALUE) },
      new Object[] { " -" + String.valueOf(Long.MAX_VALUE) + "00 ",
                     BigInteger.valueOf(Long.MAX_VALUE).multiply(
                          BigInteger.valueOf(-100L)) },
    };
  }



  /**
   * Provides a set of invalid test data.
   *
   * @return  A set of invalid test data.
   */
  @DataProvider(name="invalidValues")
  public Object[][] getInvalidValues()
  {
    return new Object[][]
    {
      new Object[] { "" },
      new Object[] { " " },
      new Object[] { "-0" },
      new Object[] { "00" },
      new Object[] { "a" },
      new Object[] { "1a" },
      new Object[] { "-" },
      new Object[] { "-a" },
      new Object[] { "123.456" },
      new Object[] { "1-23" },
      new Object[] { "1 23" },
      new Object[] { " -0 " },
      new Object[] { " 00 " },
      new Object[] { " a " },
      new Object[] { " 1a " },
      new Object[] { " - " },
      new Object[] { " -a " },
      new Object[] { " 123.456 " },
      new Object[] { " 1-23 " },
      new Object[] { " 1 23 " },
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
    IntegerMatchingRule mr = IntegerMatchingRule.getInstance();

    assertNotNull(mr.getEqualityMatchingRuleName());
    assertEquals(mr.getEqualityMatchingRuleName(), "integerMatch");

    assertNotNull(mr.getEqualityMatchingRuleOID());
    assertEquals(mr.getEqualityMatchingRuleOID(), "2.5.13.14");

    assertNotNull(mr.getEqualityMatchingRuleNameOrOID());
    assertEquals(mr.getEqualityMatchingRuleNameOrOID(), "integerMatch");

    assertNotNull(mr.getOrderingMatchingRuleName());
    assertEquals(mr.getOrderingMatchingRuleName(), "integerOrderingMatch");

    assertNotNull(mr.getOrderingMatchingRuleOID());
    assertEquals(mr.getOrderingMatchingRuleOID(), "2.5.13.15");

    assertNotNull(mr.getOrderingMatchingRuleNameOrOID());
    assertEquals(mr.getOrderingMatchingRuleNameOrOID(), "integerOrderingMatch");

    assertNull(mr.getSubstringMatchingRuleName());

    assertNull(mr.getSubstringMatchingRuleOID());

    assertNull(mr.getSubstringMatchingRuleNameOrOID());
  }
}
