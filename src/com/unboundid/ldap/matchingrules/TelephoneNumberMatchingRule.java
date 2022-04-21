/*
 * Copyright 2008-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2022 Ping Identity Corporation
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
 * Copyright (C) 2008-2022 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.matchingrules.MatchingRuleMessages.*;



/**
 * This class provides an implementation of a matching rule that may be used for
 * telephone numbers.  It will accept values with any ASCII printable character.
 * When making comparisons, spaces and dashes will be ignored.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TelephoneNumberMatchingRule
       extends SimpleMatchingRule
{
  /**
   * The name of the system property that may be used to specify the default
   * comparison policy.  If this is not specified, and if the default value is
   * not overridden by the {@link #setDefaultComparisonPolicy} method, then a
   * default policy of
   * {@link TelephoneNumberComparisonPolicy#IGNORE_ALL_NON_NUMERIC_CHARACTERS}
   * will be used.
   */
  @NotNull public static final String DEFAULT_COMPARISON_POLICY_PROPERTY =
       TelephoneNumberMatchingRule.class.getName()  +
            ".defaultComparisonPolicy";



  /**
   * The name of the system property that may be used to specify the default
   * validation policy.  If this is not specified, and if the default value is
   * not overridden by the {@link #setDefaultValidationPolicy} method, then a
   * default policy of
   * {@link TelephoneNumberValidationPolicy#ALLOW_NON_EMPTY_PRINTABLE_STRING}
   * will be used.
   */
  @NotNull public static final String DEFAULT_VALIDATION_POLICY_PROPERTY =
       TelephoneNumberMatchingRule.class.getName()  +
            ".defaultValidationPolicy";



  /**
   * The default comparison policy that will be used if none is specified.
   */
  @NotNull private static TelephoneNumberComparisonPolicy
       DEFAULT_COMPARISON_POLICY;



  /**
   * The default validation policy that will be used if none is specified.
   */
  @NotNull private static TelephoneNumberValidationPolicy
       DEFAULT_VALIDATION_POLICY;



  /**
   * The instance that will be returned from the {@code getInstance} method.
   */
  @NotNull private static TelephoneNumberMatchingRule INSTANCE;



  static
  {
    final ObjectPair<TelephoneNumberValidationPolicy,
                     TelephoneNumberComparisonPolicy> defaultPolicyPair =
         computeDefaultPolicies();

    DEFAULT_VALIDATION_POLICY = defaultPolicyPair.getFirst();
    DEFAULT_COMPARISON_POLICY = defaultPolicyPair.getSecond();
    INSTANCE = new TelephoneNumberMatchingRule(DEFAULT_VALIDATION_POLICY,
         DEFAULT_COMPARISON_POLICY);
  }



  /**
   * The name for the telephoneNumberMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_NAME =
       "telephoneNumberMatch";



  /**
   * The name for the telephoneNumberMatch equality matching rule, formatted in
   * all lowercase characters.
   */
  @NotNull static final String LOWER_EQUALITY_RULE_NAME =
       StaticUtils.toLowerCase(EQUALITY_RULE_NAME);



  /**
   * The OID for the telephoneNumberMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_OID = "2.5.13.20";



  /**
   * The name for the telephoneNumberSubstringsMatch substring matching rule.
   */
  @NotNull public static final String SUBSTRING_RULE_NAME =
       "telephoneNumberSubstringsMatch";



  /**
   * The name for the telephoneNumberSubstringsMatch substring matching rule,
   * formatted in all lowercase characters.
   */
  @NotNull static final String LOWER_SUBSTRING_RULE_NAME =
       StaticUtils.toLowerCase(SUBSTRING_RULE_NAME);



  /**
   * The OID for the telephoneNumberSubstringsMatch substring matching rule.
   */
  @NotNull public static final String SUBSTRING_RULE_OID = "2.5.13.21";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5463096544849211252L;



  // The policy to use when comparing telephone number values.
  @NotNull private final TelephoneNumberComparisonPolicy comparisonPolicy;

  // The policy to use when validating telephone number values.
  @NotNull private final TelephoneNumberValidationPolicy validationPolicy;



  /**
   * Creates a new instance of this telephone number matching rule with the
   * default validation and comparison policies.
   */
  public TelephoneNumberMatchingRule()
  {
    this(DEFAULT_VALIDATION_POLICY, DEFAULT_COMPARISON_POLICY);
  }



  /**
   * Creates a new instance of this telephone number matching rule with the
   * specified validation and comparison policies.
   *
   * @param  validationPolicy  The policy to use when validating telephone
   *                           number values.  It must not be
   *                           {@code null}.
   * @param  comparisonPolicy  The policy to use when comparing telephone number
   *                           values.  It must not be {@code null}.
   */
  public TelephoneNumberMatchingRule(
              @NotNull final TelephoneNumberValidationPolicy validationPolicy,
              @NotNull final TelephoneNumberComparisonPolicy comparisonPolicy)
  {
    Validator.ensureNotNullWithMessage(validationPolicy,
         "TelephoneNumberMatchingRule.validationPolicy must not be null.");
    Validator.ensureNotNullWithMessage(comparisonPolicy,
         "TelephoneNumberMatchingRule.comparisonPolicy must not be null.");

    this.validationPolicy = validationPolicy;
    this.comparisonPolicy = comparisonPolicy;
  }



  /**
   * Retrieves a singleton instance of this matching rule.
   *
   * @return  A singleton instance of this matching rule.
   */
  @NotNull()
  public static TelephoneNumberMatchingRule getInstance()
  {
    return INSTANCE;
  }



  /**
   * Retrieves the policy that will be used for validating telephone number
   * values.
   *
   * @return  The policy that will be used for validating telephone number
   *          values.
   */
  @NotNull()
  public TelephoneNumberValidationPolicy getValidationPolicy()
  {
    return validationPolicy;
  }



  /**
   * Retrieves the policy that will be used for validating telephone number
   * values when creating an instance of this matching rule using the default
   * constructor.
   *
   * @return  The policy that will be used for validating telephone number
   *          values when creating an instance of this matching rule using the
   *          default constructor.
   */
  @NotNull()
  public static TelephoneNumberValidationPolicy getDefaultValidationPolicy()
  {
    return DEFAULT_VALIDATION_POLICY;
  }



  /**
   * Specifies the policy that will be used for validating telephone number
   * values when creating an instance of this matching rule using the default
   * constructor.
   *
   * @param  defaultValidationPolicy  The policy that will be used for
   *                                  validating telephone number values when
   *                                  creating an instance of this matching rule
   *                                  using the default constructor.
   */
  public static synchronized void setDefaultValidationPolicy(
       @NotNull final TelephoneNumberValidationPolicy defaultValidationPolicy)
  {
    Validator.ensureNotNullWithMessage(defaultValidationPolicy,
         "TelephoneNumberMatchingRule.defaultValidationPolicy must not be " +
              "null.");

    DEFAULT_VALIDATION_POLICY = defaultValidationPolicy;
    INSTANCE = new TelephoneNumberMatchingRule(DEFAULT_VALIDATION_POLICY,
         DEFAULT_COMPARISON_POLICY);
  }



  /**
   * Retrieves the policy that will be used for comparing telephone number
   * values.
   *
   * @return  The policy that will be used for comparing telephone number
   *          values.
   */
  @NotNull()
  public TelephoneNumberComparisonPolicy getComparisonPolicy()
  {
    return comparisonPolicy;
  }



  /**
   * Retrieves the policy that will be used for comparing telephone number
   * values when creating an instance of this matching rule using the default
   * constructor.
   *
   * @return  The policy that will be used for comparing telephone number
   *          values when creating an instance of this matching rule using the
   *          default constructor.
   */
  @NotNull()
  public static TelephoneNumberComparisonPolicy getDefaultComparisonPolicy()
  {
    return DEFAULT_COMPARISON_POLICY;
  }



  /**
   * Specifies the policy that will be used for comparing telephone number
   * values when creating an instance of this matching rule using the default
   * constructor.
   *
   * @param  defaultComparisonPolicy  The policy that will be used for
   *                                  comparing telephone number values when
   *                                  creating an instance of this matching rule
   *                                  using the default constructor.
   */
  public static synchronized void setDefaultComparisonPolicy(
       @NotNull final TelephoneNumberComparisonPolicy defaultComparisonPolicy)
  {
    Validator.ensureNotNullWithMessage(defaultComparisonPolicy,
         "TelephoneNumberMatchingRule.defaultComparisonPolicy must not be " +
              "null.");

    DEFAULT_COMPARISON_POLICY = defaultComparisonPolicy;
    INSTANCE = new TelephoneNumberMatchingRule(DEFAULT_VALIDATION_POLICY,
         DEFAULT_COMPARISON_POLICY);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getEqualityMatchingRuleName()
  {
    return EQUALITY_RULE_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getEqualityMatchingRuleOID()
  {
    return EQUALITY_RULE_OID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getOrderingMatchingRuleName()
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getOrderingMatchingRuleOID()
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSubstringMatchingRuleName()
  {
    return SUBSTRING_RULE_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSubstringMatchingRuleOID()
  {
    return SUBSTRING_RULE_OID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int compareValues(@NotNull final ASN1OctetString value1,
                           @NotNull final ASN1OctetString value2)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_TELEPHONE_NUMBER_ORDERING_MATCHING_NOT_SUPPORTED.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1OctetString normalize(@NotNull final ASN1OctetString value)
         throws LDAPException
  {
    validationPolicy.validateValue(value, false);
    return comparisonPolicy.normalizeValue(value);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1OctetString normalizeSubstring(
                              @NotNull final ASN1OctetString value,
                              final byte substringType)
         throws LDAPException
  {
    validationPolicy.validateValue(value, true);
    return comparisonPolicy.normalizeValue(value);
  }



  /**
   * Computes the default validation and comparison policies that should be used
   * for this class.
   *
   * @return  An object pair in which the first element is the selected default
   *          validation policy and the second element is the selected default
   *          comparison policy.
   */
  @NotNull()
  static ObjectPair<TelephoneNumberValidationPolicy,
                   TelephoneNumberComparisonPolicy> computeDefaultPolicies()
  {
    // Determine the appropriate default validation policy.
    TelephoneNumberValidationPolicy validationPolicy = null;
    final String validationPropertyValue =
         StaticUtils.getSystemProperty(DEFAULT_VALIDATION_POLICY_PROPERTY);
    if (validationPropertyValue != null)
    {
      final String normalizedPropertyValue =
           validationPropertyValue.toUpperCase().replace('-', '_');
      for (final TelephoneNumberValidationPolicy v :
           TelephoneNumberValidationPolicy.values())
      {
        if (v.name().equals(normalizedPropertyValue))
        {
          validationPolicy = v;
          break;
        }
      }
    }

    if (validationPolicy == null)
    {
      validationPolicy =
           TelephoneNumberValidationPolicy.ALLOW_NON_EMPTY_PRINTABLE_STRING;
    }


    // Determine the appropriate default comparison policy.
    TelephoneNumberComparisonPolicy comparisonPolicy = null;
    final String comparisonPropertyValue =
         StaticUtils.getSystemProperty(DEFAULT_COMPARISON_POLICY_PROPERTY);
    if (comparisonPropertyValue != null)
    {
      final String normalizedPropertyValue =
           comparisonPropertyValue.toUpperCase().replace('-', '_');
      for (final TelephoneNumberComparisonPolicy v :
           TelephoneNumberComparisonPolicy.values())
      {
        if (v.name().equals(normalizedPropertyValue))
        {
          comparisonPolicy = v;
          break;
        }
      }
    }

    if (comparisonPolicy == null)
    {
      comparisonPolicy =
           TelephoneNumberComparisonPolicy.IGNORE_ALL_NON_NUMERIC_CHARACTERS;
    }


    return new ObjectPair<>(validationPolicy, comparisonPolicy);
  }
}
