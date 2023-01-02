/*
 * Copyright 2008-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2023 Ping Identity Corporation
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
 * Copyright (C) 2008-2023 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.ObjectPair;



/**
 * This class provides a set of test cases for the telephone number matching
 * rule.
 */
public class TelephoneNumberMatchingRuleTestCase
       extends MatchingRuleTestCase
{
  /**
   * Provides test coverage for a number of general methods for the matching
   * rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneralMatchingRuleMethods()
         throws Exception
  {
    final TelephoneNumberMatchingRule mr =
         TelephoneNumberMatchingRule.getInstance();
    assertNotNull(mr);

    assertEquals(mr.getEqualityMatchingRuleName(), "telephoneNumberMatch");

    assertEquals(mr.getEqualityMatchingRuleOID(), "2.5.13.20");

    assertNull(mr.getOrderingMatchingRuleName());

    assertNull(mr.getOrderingMatchingRuleOID());

    assertEquals(mr.getSubstringMatchingRuleName(),
         "telephoneNumberSubstringsMatch");

    assertEquals(mr.getSubstringMatchingRuleOID(), "2.5.13.21");
  }



  /**
   * Tests the ability to configure the default validation and comparison
   * policies.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultPolicies()
         throws Exception
  {
    TelephoneNumberMatchingRule mr = new TelephoneNumberMatchingRule();
    assertEquals(mr.getValidationPolicy(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(mr.getComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);

    assertEquals(TelephoneNumberMatchingRule.getDefaultValidationPolicy(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(TelephoneNumberMatchingRule.getDefaultComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);

    TelephoneNumberMatchingRule.setDefaultValidationPolicy(
         TelephoneNumberValidationPolicy.ENFORCE_STRICT_X520_COMPLIANCE);
    assertEquals(TelephoneNumberMatchingRule.getDefaultValidationPolicy(),
         TelephoneNumberValidationPolicy.ENFORCE_STRICT_X520_COMPLIANCE);
    assertEquals(TelephoneNumberMatchingRule.getDefaultComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);

    mr = new TelephoneNumberMatchingRule();
    assertEquals(mr.getValidationPolicy(),
         TelephoneNumberValidationPolicy.ENFORCE_STRICT_X520_COMPLIANCE);
    assertEquals(mr.getComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);

    mr = TelephoneNumberMatchingRule.getInstance();
    assertEquals(mr.getValidationPolicy(),
         TelephoneNumberValidationPolicy.ENFORCE_STRICT_X520_COMPLIANCE);
    assertEquals(mr.getComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);

    TelephoneNumberMatchingRule.setDefaultComparisonPolicy(
         TelephoneNumberComparisonPolicy.IGNORE_ONLY_SPACES_AND_DASHES);
    assertEquals(TelephoneNumberMatchingRule.getDefaultValidationPolicy(),
         TelephoneNumberValidationPolicy.ENFORCE_STRICT_X520_COMPLIANCE);
    assertEquals(TelephoneNumberMatchingRule.getDefaultComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ONLY_SPACES_AND_DASHES);

    mr = new TelephoneNumberMatchingRule();
    assertEquals(mr.getValidationPolicy(),
         TelephoneNumberValidationPolicy.ENFORCE_STRICT_X520_COMPLIANCE);
    assertEquals(mr.getComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ONLY_SPACES_AND_DASHES);

    mr = TelephoneNumberMatchingRule.getInstance();
    assertEquals(mr.getValidationPolicy(),
         TelephoneNumberValidationPolicy.ENFORCE_STRICT_X520_COMPLIANCE);
    assertEquals(mr.getComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ONLY_SPACES_AND_DASHES);

    TelephoneNumberMatchingRule.setDefaultValidationPolicy(
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    TelephoneNumberMatchingRule.setDefaultComparisonPolicy(
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);
    assertEquals(TelephoneNumberMatchingRule.getDefaultValidationPolicy(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(TelephoneNumberMatchingRule.getDefaultComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);

    mr = new TelephoneNumberMatchingRule();
    assertEquals(mr.getValidationPolicy(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(mr.getComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);

    mr = TelephoneNumberMatchingRule.getInstance();
    assertEquals(mr.getValidationPolicy(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(mr.getComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);
  }



  /**
   * Tests the behavior when working with values that are valid X.520 telephone
   * numbers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidX520TelephoneNumbers()
         throws Exception
  {
    final ASN1OctetString v1 = new ASN1OctetString("+1 123 456-7890");
    final ASN1OctetString v2 = new ASN1OctetString("+1 123 456-7890");
    final ASN1OctetString v3 = new ASN1OctetString("+11234567890");
    final ASN1OctetString v4 = new ASN1OctetString("+9 876 543-2100");

    TelephoneNumberMatchingRule mr = new TelephoneNumberMatchingRule(
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING,
         TelephoneNumberComparisonPolicy.IGNORE_ONLY_SPACES_AND_DASHES);

    assertEquals(mr.normalize(v1).stringValue(), "+11234567890");
    assertEquals(mr.normalize(v2).stringValue(), "+11234567890");
    assertEquals(mr.normalize(v3).stringValue(), "+11234567890");
    assertEquals(mr.normalize(v4).stringValue(), "+98765432100");

    assertEquals(
         mr.normalizeSubstring(v1, MatchingRule.SUBSTRING_TYPE_SUBANY).
              stringValue(),
         "+11234567890");
    assertEquals(
         mr.normalizeSubstring(v2, MatchingRule.SUBSTRING_TYPE_SUBANY).
              stringValue(),
         "+11234567890");
    assertEquals(
         mr.normalizeSubstring(v3, MatchingRule.SUBSTRING_TYPE_SUBANY).
              stringValue(),
         "+11234567890");
    assertEquals(
         mr.normalizeSubstring(v4, MatchingRule.SUBSTRING_TYPE_SUBANY).
              stringValue(),
         "+98765432100");

    try
    {
      mr.compareValues(v1, v2);
      fail("Expected an exception when trying to compare telephoneNumber " +
           "values.");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }

    assertTrue(mr.valuesMatch(v1, v1));
    assertTrue(mr.valuesMatch(v1, v2));
    assertTrue(mr.valuesMatch(v1, v3));
    assertFalse(mr.valuesMatch(v1, v4));

    assertTrue(mr.matchesSubstring(v1, v1, null, null));
    assertTrue(mr.matchesSubstring(v1, v2, null, null));
    assertTrue(mr.matchesSubstring(v1, v3, null, null));
    assertFalse(mr.matchesSubstring(v1, v4, null, null));
  }



  /**
   * Tests the ability to set default policies based on system properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testComputeDefaultPolicies()
         throws Exception
  {
    assertNull(System.getProperty(
         TelephoneNumberMatchingRule.DEFAULT_VALIDATION_POLICY_PROPERTY));
    assertNull(System.getProperty(
         TelephoneNumberMatchingRule.DEFAULT_COMPARISON_POLICY_PROPERTY));
    assertEquals(TelephoneNumberMatchingRule.getDefaultValidationPolicy(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(TelephoneNumberMatchingRule.getDefaultComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);

    ObjectPair<TelephoneNumberValidationPolicy,TelephoneNumberComparisonPolicy>
         policies = TelephoneNumberMatchingRule.computeDefaultPolicies();
    assertEquals(policies.getFirst(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(policies.getSecond(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);


    System.setProperty(
         TelephoneNumberMatchingRule.DEFAULT_VALIDATION_POLICY_PROPERTY,
         TelephoneNumberValidationPolicy.
              ALLOW_NON_EMPTY_PRINTABLE_STRING_WITH_AT_LEAST_ONE_DIGIT.name());
    System.setProperty(
         TelephoneNumberMatchingRule.DEFAULT_COMPARISON_POLICY_PROPERTY,
         TelephoneNumberComparisonPolicy.IGNORE_ONLY_SPACES_AND_DASHES.name());

    policies = TelephoneNumberMatchingRule.computeDefaultPolicies();
    assertEquals(policies.getFirst(),
         TelephoneNumberValidationPolicy.
              ALLOW_NON_EMPTY_PRINTABLE_STRING_WITH_AT_LEAST_ONE_DIGIT);
    assertEquals(policies.getSecond(),
         TelephoneNumberComparisonPolicy.IGNORE_ONLY_SPACES_AND_DASHES);
    assertEquals(TelephoneNumberMatchingRule.getDefaultValidationPolicy(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(TelephoneNumberMatchingRule.getDefaultComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);


    System.setProperty(
         TelephoneNumberMatchingRule.DEFAULT_VALIDATION_POLICY_PROPERTY,
         "invalid");
    System.setProperty(
         TelephoneNumberMatchingRule.DEFAULT_COMPARISON_POLICY_PROPERTY,
         "invalid");

    policies = TelephoneNumberMatchingRule.computeDefaultPolicies();
    assertEquals(policies.getFirst(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(policies.getSecond(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);
    assertEquals(TelephoneNumberMatchingRule.getDefaultValidationPolicy(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(TelephoneNumberMatchingRule.getDefaultComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);


    System.clearProperty(
         TelephoneNumberMatchingRule.DEFAULT_VALIDATION_POLICY_PROPERTY);
    System.clearProperty(
         TelephoneNumberMatchingRule.DEFAULT_COMPARISON_POLICY_PROPERTY);

    policies = TelephoneNumberMatchingRule.computeDefaultPolicies();
    assertEquals(policies.getFirst(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(policies.getSecond(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);
    assertEquals(TelephoneNumberMatchingRule.getDefaultValidationPolicy(),
         TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING);
    assertEquals(TelephoneNumberMatchingRule.getDefaultComparisonPolicy(),
         TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS);
  }
}
