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
import com.unboundid.ldap.sdk.DNTestCase;
import com.unboundid.ldap.sdk.LDAPException;



/**
 * This class provides a set of test cases for the DistinguishedNameMatchingRule
 * class.
 */
public class DistinguishedNameMatchingRuleTestCase
       extends MatchingRuleTestCase
{
  /**
   * Tests the {@code valuesMatch} method with a set of valid DNs.  They
   * should always match.
   *
   * @param  dn1  The first DN to compare.
   * @param  dn2  The second DN to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidDNs")
  public void testValuesMatch(String dn1, String dn2)
         throws Exception
  {
    DistinguishedNameMatchingRule mr =
         DistinguishedNameMatchingRule.getInstance();

    assertTrue(mr.valuesMatch(new ASN1OctetString(dn1),
                              new ASN1OctetString(dn2)));
  }



  /**
   * Tests the {@code valuesMatch} method with a set of valid DNs.  They
   * should not match.
   *
   * @param  dn1  The first DN to compare.
   * @param  dn2  The second DN to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testNonMatchingDNs")
  public void testValuesMatchNonMatching(String dn1, String dn2)
         throws Exception
  {
    DistinguishedNameMatchingRule mr =
         DistinguishedNameMatchingRule.getInstance();

    assertFalse(mr.valuesMatch(new ASN1OctetString(dn1),
                               new ASN1OctetString(dn2)));
  }



  /**
   * Tests the {@code valuesMatch} method with an invalid DN.
   *
   * @param  invalidDN  The invalid DN to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testInvalidDNs")
  public void testValuesMatchInvalid(String invalidDN)
         throws Exception
  {
    DistinguishedNameMatchingRule mr =
         DistinguishedNameMatchingRule.getInstance();

    try
    {
      mr.valuesMatch(new ASN1OctetString(invalidDN),
                     new ASN1OctetString("dc=example,dc=com"));
      fail("Expected an exception with an invalid first DN.");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }

    try
    {
      mr.valuesMatch(new ASN1OctetString("dc=example,dc=com"),
                     new ASN1OctetString(invalidDN));
      fail("Expected an exception with an invalid second DN.");
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
   * @param  dn1  The first DN value.
   * @param  dn2  The second DN value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidDNs",
        expectedExceptions = { LDAPException.class })
  public void testMatchesSubstring(String dn1, String dn2)
         throws Exception
  {
    DistinguishedNameMatchingRule mr =
         DistinguishedNameMatchingRule.getInstance();

    mr.matchesSubstring(new ASN1OctetString(dn1),
                        new ASN1OctetString(dn2), null, null);
  }



  /**
   * Tests to ensure that the {@code compareValues} method will always throw
   * an exception.
   *
   * @param  dn1  The first DN value.
   * @param  dn2  The second DN value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidDNs",
        expectedExceptions = { LDAPException.class })
  public void testCompareValues(String dn1, String dn2)
         throws Exception
  {
    DistinguishedNameMatchingRule mr =
         DistinguishedNameMatchingRule.getInstance();

    mr.compareValues(new ASN1OctetString(dn1), new ASN1OctetString(dn2));
  }



  /**
   * Tests to ensure that the {@code normalize} method returns the appropriate
   * value when given valid DNs.
   *
   * @param  rawDN         The raw DN to normalize.
   * @param  normalizedDN  The expected normalized representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidDNs")
  public void testNormalizeValid(String rawDN, String normalizedDN)
         throws Exception
  {
    DistinguishedNameMatchingRule mr =
         DistinguishedNameMatchingRule.getInstance();

    assertEquals(mr.normalize(new ASN1OctetString(rawDN)),
                 new ASN1OctetString(normalizedDN));
  }



  /**
   * Tests to ensure that the {@code normalize} method throws an exception when
   * given values that aren't valid DNs.
   *
   * @param  invalidDN  A string that cannot be parsed as a valid DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testInvalidDNs",
        expectedExceptions = { LDAPException.class })
  public void testNormalizeInvalid(String invalidDN)
         throws Exception
  {
    DistinguishedNameMatchingRule mr =
         DistinguishedNameMatchingRule.getInstance();

    mr.normalize(new ASN1OctetString(invalidDN));
  }



  /**
   * Tests to ensure that the {@code normalizeSubstring} method always throws an
   * exception.
   *
   * @param  dn1  The first DN.
   * @param  dn2  The second DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testValidDNs",
        expectedExceptions = { LDAPException.class })
  public void testNormalizeSubstring(String dn1, String dn2)
         throws Exception
  {
    DistinguishedNameMatchingRule mr =
         DistinguishedNameMatchingRule.getInstance();

    mr.normalizeSubstring(new ASN1OctetString(dn1), (byte) 0x80);
  }



  /**
   * Retrieves a set of strings that may be used to create valid DNs.
   *
   * @return  A set of strings that may be used to create valid DNs.
   */
  @DataProvider(name = "testValidDNs")
  public Object[][] getTestValidDNs()
  {
    return new DNTestCase().getTestValidDNs();
  }



  /**
   * Retrieves a set of strings that cannot be used to create valid DNs.
   *
   * @return  A set of strings that cannot be used to create valid DNs.
   */
  @DataProvider(name = "testInvalidDNs")
  public Object[][] getTestInvalidDNs()
  {
    return new DNTestCase().getTestInvalidDNs();
  }



  /**
   * Retrieves a set of strings that may be used to create valid DNs, but
   * the paired DN values do not match.
   *
   * @return  A set of strings that may be used to create valid DNs.
   */
  @DataProvider(name = "testNonMatchingDNs")
  public Object[][] getTestNonMatchingDNs()
  {
    return new Object[][]
    {
      new Object[] { "dc=example,dc=com", "o=example.com" },
      new Object[] { "dc=example,dc=com", "dc=com" },
      new Object[] { "dc=com", "dc=example,dc=com" },
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
    DistinguishedNameMatchingRule mr =
         DistinguishedNameMatchingRule.getInstance();

    assertNotNull(mr.getEqualityMatchingRuleName());
    assertEquals(mr.getEqualityMatchingRuleName(), "distinguishedNameMatch");

    assertNotNull(mr.getEqualityMatchingRuleOID());
    assertEquals(mr.getEqualityMatchingRuleOID(), "2.5.13.1");

    assertNotNull(mr.getEqualityMatchingRuleNameOrOID());
    assertEquals(mr.getEqualityMatchingRuleNameOrOID(),
         "distinguishedNameMatch");

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
    final DistinguishedNameMatchingRule mr =
         DistinguishedNameMatchingRule.getInstance();

    final ASN1OctetString assertionValue =
         new ASN1OctetString("dc=example,dc=com");
    assertFalse(mr.matchesAnyValue(assertionValue, null));
    assertFalse(mr.matchesAnyValue(assertionValue, new ASN1OctetString[0]));

    final ASN1OctetString[] attributeValues =
    {
      new ASN1OctetString("o=example.com"),
      new ASN1OctetString("not a valid dn"),
      new ASN1OctetString("dc=example,dc=com"),
      new ASN1OctetString("ou=People,dc=example,dc=com")
    };


    assertFalse(mr.matchesAnyValue(null, attributeValues));

    assertTrue(mr.matchesAnyValue(assertionValue, attributeValues));
    assertTrue(mr.matchesAnyValue(new ASN1OctetString("o=example.com"),
         attributeValues));
    assertTrue(mr.matchesAnyValue(
         new ASN1OctetString("ou=People,dc=example,dc=com"), attributeValues));
    assertTrue(mr.matchesAnyValue(
         new ASN1OctetString("OU = people , DC = example , DC = com"),
         attributeValues));

    assertFalse(mr.matchesAnyValue(new ASN1OctetString("o=test"),
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
