/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.io.Serializable;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.jsonfilter.
            JSONObjectExactMatchingRule;
import com.unboundid.util.Debug;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines the API for an LDAP matching rule, which may be used to
 * determine whether two values are equal to each other, and to normalize values
 * so that they may be more easily compared.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class MatchingRule
       implements Serializable
{
  /**
   * The substring element type used for subInitial substring assertion
   * components.
   */
  public static final byte SUBSTRING_TYPE_SUBINITIAL = (byte) 0x80;



  /**
   * The substring element type used for subAny substring assertion components.
   */
  public static final byte SUBSTRING_TYPE_SUBANY = (byte) 0x81;



  /**
   * The substring element type used for subFinal substring assertion
   * components.
   */
  public static final byte SUBSTRING_TYPE_SUBFINAL = (byte) 0x82;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6050276733546358513L;



  /**
   * Creates a new instance of this matching rule.
   */
  protected MatchingRule()
  {
    // No implementation is required.
  }



  /**
   * Retrieves the name for this matching rule when used to perform equality
   * matching, if appropriate.
   *
   * @return  The name for this matching rule when used to perform equality
   *          matching, or {@code null} if this matching rule is not intended
   *          to be used for equality matching.
   */
  @Nullable()
  public abstract String getEqualityMatchingRuleName();



  /**
   * Retrieves the OID for this matching rule when used to perform equality
   * matching, if appropriate.
   *
   * @return  The OID for this matching rule when used to perform equality
   *          matching, or {@code null} if this matching rule is not intended
   *          to be used for equality matching.
   */
  @Nullable()
  public abstract String getEqualityMatchingRuleOID();



  /**
   * Retrieves the name for this matching rule when used to perform equality
   * matching if defined, or the OID if no name is available.
   *
   * @return  The name or OID for this matching rule when used to perform
   *          equality matching, or {@code null} if this matching rule cannot
   *          be used to perform equality matching.
   */
  @Nullable()
  public String getEqualityMatchingRuleNameOrOID()
  {
    final String name = getEqualityMatchingRuleName();
    if (name == null)
    {
      return getEqualityMatchingRuleOID();
    }
    else
    {
      return name;
    }
  }



  /**
   * Retrieves the name for this matching rule when used to perform ordering
   * matching, if appropriate.
   *
   * @return  The name for this matching rule when used to perform ordering
   *          matching, or {@code null} if this matching rule is not intended
   *          to be used for ordering matching.
   */
  @Nullable()
  public abstract String getOrderingMatchingRuleName();



  /**
   * Retrieves the OID for this matching rule when used to perform ordering
   * matching, if appropriate.
   *
   * @return  The OID for this matching rule when used to perform ordering
   *          matching, or {@code null} if this matching rule is not intended
   *          to be used for ordering matching.
   */
  @Nullable()
  public abstract String getOrderingMatchingRuleOID();



  /**
   * Retrieves the name for this matching rule when used to perform ordering
   * matching if defined, or the OID if no name is available.
   *
   * @return  The name or OID for this matching rule when used to perform
   *          ordering matching, or {@code null} if this matching rule cannot
   *          be used to perform equality matching.
   */
  @Nullable()
  public String getOrderingMatchingRuleNameOrOID()
  {
    final String name = getOrderingMatchingRuleName();
    if (name == null)
    {
      return getOrderingMatchingRuleOID();
    }
    else
    {
      return name;
    }
  }



  /**
   * Retrieves the name for this matching rule when used to perform substring
   * matching, if appropriate.
   *
   * @return  The name for this matching rule when used to perform substring
   *          matching, or {@code null} if this matching rule is not intended
   *          to be used for substring matching.
   */
  @Nullable()
  public abstract String getSubstringMatchingRuleName();



  /**
   * Retrieves the OID for this matching rule when used to perform substring
   * matching, if appropriate.
   *
   * @return  The OID for this matching rule when used to perform substring
   *          matching, or {@code null} if this matching rule is not intended
   *          to be used for substring matching.
   */
  @Nullable()
  public abstract String getSubstringMatchingRuleOID();



  /**
   * Retrieves the name for this matching rule when used to perform substring
   * matching if defined, or the OID if no name is available.
   *
   * @return  The name or OID for this matching rule when used to perform
   *          substring matching, or {@code null} if this matching rule cannot
   *          be used to perform equality matching.
   */
  @Nullable()
  public String getSubstringMatchingRuleNameOrOID()
  {
    final String name = getSubstringMatchingRuleName();
    if (name == null)
    {
      return getSubstringMatchingRuleOID();
    }
    else
    {
      return name;
    }
  }



  /**
   * Indicates whether the provided values are equal to each other, according to
   * the constraints of this matching rule.
   *
   * @param  value1  The first value for which to make the determination.
   * @param  value2  The second value for which to make the determination.
   *
   * @return  {@code true} if the provided values are considered equal, or
   *          {@code false} if not.
   *
   * @throws  LDAPException  If a problem occurs while making the determination,
   *                         or if this matching rule does not support equality
   *                         matching.
   */
  public abstract boolean valuesMatch(@NotNull ASN1OctetString value1,
                                      @NotNull ASN1OctetString value2)
         throws LDAPException;



  /**
   * Indicates whether the provided assertion value matches any of the provided
   * attribute values.
   *
   * @param  assertionValue   The assertion value for which to make the
   *                          determination.
   * @param  attributeValues  The set of attribute values to compare against the
   *                          provided assertion value.
   *
   * @return  {@code true} if the provided assertion value matches any of the
   *          given attribute values, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem occurs while making the determination,
   *                         or if this matching rule does not support equality
   *                         matching.
   */
  public boolean matchesAnyValue(@NotNull final ASN1OctetString assertionValue,
                      @NotNull final ASN1OctetString[] attributeValues)
         throws LDAPException
  {
    if ((assertionValue == null) || (attributeValues == null) ||
        (attributeValues.length == 0))
    {
      return false;
    }

    boolean exceptionOnEveryAttempt = true;
    LDAPException firstException = null;
    for (final ASN1OctetString attributeValue : attributeValues)
    {
      try
      {
        if (valuesMatch(assertionValue, attributeValue))
        {
          return true;
        }

        exceptionOnEveryAttempt = false;
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        if (firstException == null)
        {
          firstException = le;
        }
      }
    }

    if (exceptionOnEveryAttempt)
    {
      throw firstException;
    }

    return false;
  }



  /**
   * Indicates whether the provided value matches the given substring assertion,
   * according to the constraints of this matching rule.
   *
   * @param  value       The value for which to make the determination.
   * @param  subInitial  The subInitial portion of the substring assertion, or
   *                     {@code null} if there is no subInitial element.
   * @param  subAny      The subAny elements of the substring assertion, or
   *                     {@code null} if there are no subAny elements.
   * @param  subFinal    The subFinal portion of the substring assertion, or
   *                     {@code null} if there is no subFinal element.
   *
   * @return  {@code true} if the provided value matches the substring
   *          assertion, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem occurs while making the determination,
   *                         or if this matching rule does not support substring
   *                         matching.
   */
  public abstract boolean matchesSubstring(@NotNull ASN1OctetString value,
                                           @Nullable ASN1OctetString subInitial,
                                           @Nullable ASN1OctetString[] subAny,
                                           @Nullable ASN1OctetString subFinal)
         throws LDAPException;



  /**
   * Compares the provided values to determine their relative order in a sorted
   * list.
   *
   * @param  value1  The first value to compare.
   * @param  value2  The second value to compare.
   *
   * @return  A negative value if {@code value1} should come before
   *          {@code value2} in a sorted list, a positive value if
   *          {@code value1} should come after {@code value2} in a sorted list,
   *          or zero if the values are equal or there is no distinction between
   *          their orders in a sorted list.
   *
   * @throws  LDAPException  If a problem occurs while making the determination,
   *                         or if this matching rule does not support ordering
   *                         matching.
   */
  public abstract int compareValues(@NotNull ASN1OctetString value1,
                                    @NotNull ASN1OctetString value2)
         throws LDAPException;



  /**
   * Normalizes the provided value for easier matching.
   *
   * @param  value  The value to be normalized.
   *
   * @return  The normalized form of the provided value.
   *
   * @throws  LDAPException  If a problem occurs while normalizing the provided
   *                         value.
   */
  @NotNull()
  public abstract ASN1OctetString normalize(@NotNull ASN1OctetString value)
         throws LDAPException;



  /**
   * Normalizes the provided value for use as part of a substring assertion.
   *
   * @param  value          The value to be normalized for use as part of a
   *                        substring assertion.
   * @param  substringType  The substring assertion component type for the
   *                        provided value.  It should be one of
   *                        {@code SUBSTRING_TYPE_SUBINITIAL},
   *                        {@code SUBSTRING_TYPE_SUBANY}, or
   *                        {@code SUBSTRING_TYPE_SUBFINAL}.
   *
   * @return  The normalized form of the provided value.
   *
   * @throws  LDAPException  If a problem occurs while normalizing the provided
   *                         value.
   */
  @NotNull()
  public abstract ASN1OctetString normalizeSubstring(
                                       @NotNull ASN1OctetString value,
                                       byte substringType)
         throws LDAPException;



  /**
   * Attempts to select the appropriate matching rule to use for equality
   * matching against the specified attribute.  If an appropriate matching rule
   * cannot be determined, then the default equality matching rule will be
   * selected.
   *
   * @param  attrName  The name of the attribute to examine in the provided
   *                   schema.
   * @param  schema    The schema to examine to make the appropriate
   *                   determination.  If this is {@code null}, then the default
   *                   equality matching rule will be selected.
   *
   * @return  The selected matching rule.
   */
  @NotNull()
  public static MatchingRule selectEqualityMatchingRule(
                                  @NotNull final String attrName,
                                  @Nullable final Schema schema)
  {
    return selectEqualityMatchingRule(attrName, null, schema);
  }



  /**
   * Attempts to select the appropriate matching rule to use for equality
   * matching against the specified attribute.  If an appropriate matching rule
   * cannot be determined, then the default equality matching rule will be
   * selected.
   *
   * @param  attrName  The name of the attribute to examine in the provided
   *                   schema.  It may be {@code null} if the matching rule
   *                   should be selected using the matching rule ID.
   * @param  ruleID    The OID of the desired matching rule.  It may be
   *                   {@code null} if the matching rule should be selected only
   *                   using the attribute name.  If a rule ID is provided, then
   *                   it will be the only criteria used to select the matching
   *                   rule.
   * @param  schema    The schema to examine to make the appropriate
   *                   determination.  If this is {@code null} and no rule ID
   *                   was provided, then the default equality matching rule
   *                   will be selected.
   *
   * @return  The selected matching rule.
   */
  @NotNull()
  public static MatchingRule selectEqualityMatchingRule(
                                  @Nullable final String attrName,
                                  @Nullable final String ruleID,
                                  @Nullable final Schema schema)
  {
    if (ruleID != null)
    {
      return selectEqualityMatchingRule(ruleID);
    }

    if ((attrName == null) || (schema == null))
    {
      return getDefaultEqualityMatchingRule();
    }

    final AttributeTypeDefinition attrType = schema.getAttributeType(attrName);
    if (attrType == null)
    {
      return getDefaultEqualityMatchingRule();
    }

    final String mrName = attrType.getEqualityMatchingRule(schema);
    if (mrName != null)
    {
      return selectEqualityMatchingRule(mrName);
    }

    final String syntaxOID = attrType.getBaseSyntaxOID(schema);
    if (syntaxOID != null)
    {
      return selectMatchingRuleForSyntax(syntaxOID);
    }

    return getDefaultEqualityMatchingRule();
  }



  /**
   * Attempts to select the appropriate matching rule to use for equality
   * matching using the specified matching rule.  If an appropriate matching
   * rule cannot be determined, then the default equality matching rule will be
   * selected.
   *
   * @param  ruleID  The name or OID of the desired matching rule.
   *
   * @return  The selected matching rule.
   */
  @NotNull()
  public static MatchingRule selectEqualityMatchingRule(
                                  @NotNull final String ruleID)
  {
    if ((ruleID == null) || ruleID.isEmpty())
    {
      return getDefaultEqualityMatchingRule();
    }

    final String lowerName = StaticUtils.toLowerCase(ruleID);
    if (lowerName.equals(BooleanMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
        lowerName.equals(BooleanMatchingRule.EQUALITY_RULE_OID))
    {
      return BooleanMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseExactStringMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(CaseExactStringMatchingRule.EQUALITY_RULE_OID) ||
             lowerName.equals("caseexactia5match") ||
             lowerName.equals("1.3.6.1.4.1.1466.109.114.1"))
    {
      return CaseExactStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseIgnoreListMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(CaseIgnoreListMatchingRule.EQUALITY_RULE_OID))
    {
      return CaseIgnoreListMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseIgnoreStringMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(CaseIgnoreStringMatchingRule.EQUALITY_RULE_OID) ||
             lowerName.equals("caseignoreia5match") ||
             lowerName.equals("1.3.6.1.4.1.1466.109.114.2"))
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  DistinguishedNameMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(
                  DistinguishedNameMatchingRule.EQUALITY_RULE_OID) ||
             lowerName.equals("uniquemembermatch") ||
             lowerName.equals("2.5.13.23"))
    {
      // NOTE -- Technically uniqueMember should use a name and optional UID
      // matching rule, but the SDK doesn't currently provide one and the
      // distinguished name matching rule should be sufficient the vast
      // majority of the time.
      return DistinguishedNameMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  GeneralizedTimeMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(GeneralizedTimeMatchingRule.EQUALITY_RULE_OID))
    {
      return GeneralizedTimeMatchingRule.getInstance();
    }
    else if (lowerName.equals(IntegerMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(IntegerMatchingRule.EQUALITY_RULE_OID))
    {
      return IntegerMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  NumericStringMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(NumericStringMatchingRule.EQUALITY_RULE_OID))
    {
      return NumericStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  OctetStringMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(OctetStringMatchingRule.EQUALITY_RULE_OID))
    {
      return OctetStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  TelephoneNumberMatchingRule.LOWER_EQUALITY_RULE_NAME) ||
             lowerName.equals(TelephoneNumberMatchingRule.EQUALITY_RULE_OID))
    {
      return TelephoneNumberMatchingRule.getInstance();
    }
    else if (lowerName.equals("jsonobjectexactmatch") ||
             lowerName.equals("1.3.6.1.4.1.30221.2.4.12"))
    {
      return JSONObjectExactMatchingRule.getInstance();
    }
    else
    {
      return getDefaultEqualityMatchingRule();
    }
  }



  /**
   * Retrieves the default matching rule that will be used for equality matching
   * if no other matching rule is specified or available.  The rule returned
   * will perform case-ignore string matching.
   *
   * @return  The default matching rule that will be used for equality matching
   *          if no other matching rule is specified or available.
   */
  @NotNull()
  public static MatchingRule getDefaultEqualityMatchingRule()
  {
    return CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Attempts to select the appropriate matching rule to use for ordering
   * matching against the specified attribute.  If an appropriate matching rule
   * cannot be determined, then the default ordering matching rule will be
   * selected.
   *
   * @param  attrName  The name of the attribute to examine in the provided
   *                   schema.
   * @param  schema    The schema to examine to make the appropriate
   *                   determination.  If this is {@code null}, then the default
   *                   ordering matching rule will be selected.
   *
   * @return  The selected matching rule.
   */
  @NotNull()
  public static MatchingRule selectOrderingMatchingRule(
                                  @NotNull final String attrName,
                                  @Nullable final Schema schema)
  {
    return selectOrderingMatchingRule(attrName, null, schema);
  }



  /**
   * Attempts to select the appropriate matching rule to use for ordering
   * matching against the specified attribute.  If an appropriate matching rule
   * cannot be determined, then the default ordering matching rule will be
   * selected.
   *
   * @param  attrName  The name of the attribute to examine in the provided
   *                   schema.  It may be {@code null} if the matching rule
   *                   should be selected using the matching rule ID.
   * @param  ruleID    The OID of the desired matching rule.  It may be
   *                   {@code null} if the matching rule should be selected only
   *                   using the attribute name.  If a rule ID is provided, then
   *                   it will be the only criteria used to select the matching
   *                   rule.
   * @param  schema    The schema to examine to make the appropriate
   *                   determination.  If this is {@code null} and no rule ID
   *                   was provided, then the default ordering matching rule
   *                   will be selected.
   *
   * @return  The selected matching rule.
   */
  @NotNull()
  public static MatchingRule selectOrderingMatchingRule(
                                  @Nullable final String attrName,
                                  @Nullable final String ruleID,
                                  @Nullable final Schema schema)
  {
    if (ruleID != null)
    {
      return selectOrderingMatchingRule(ruleID);
    }

    if ((attrName == null) || (schema == null))
    {
      return getDefaultOrderingMatchingRule();
    }

    final AttributeTypeDefinition attrType = schema.getAttributeType(attrName);
    if (attrType == null)
    {
      return getDefaultOrderingMatchingRule();
    }

    final String mrName = attrType.getOrderingMatchingRule(schema);
    if (mrName != null)
    {
      return selectOrderingMatchingRule(mrName);
    }

    final String emrName = attrType.getEqualityMatchingRule(schema);
    if (emrName != null)
    {
      final MatchingRule mr = selectEqualityMatchingRule(emrName);
      if ((mr != null) && (mr.getOrderingMatchingRuleOID() != null))
      {
        return mr;
      }
    }

    final String syntaxOID = attrType.getBaseSyntaxOID(schema);
    if (syntaxOID != null)
    {
      return selectMatchingRuleForSyntax(syntaxOID);
    }

    return getDefaultOrderingMatchingRule();
  }



  /**
   * Attempts to select the appropriate matching rule to use for ordering
   * matching using the specified matching rule.  If an appropriate matching
   * rule cannot be determined, then the default ordering matching rule will be
   * selected.
   *
   * @param  ruleID  The name or OID of the desired matching rule.
   *
   * @return  The selected matching rule.
   */
  @NotNull()
  public static MatchingRule selectOrderingMatchingRule(
                                  @NotNull final String ruleID)
  {
    if ((ruleID == null) || ruleID.isEmpty())
    {
      return getDefaultOrderingMatchingRule();
    }

    final String lowerName = StaticUtils.toLowerCase(ruleID);
    if (lowerName.equals(
             CaseExactStringMatchingRule.LOWER_ORDERING_RULE_NAME) ||
        lowerName.equals(CaseExactStringMatchingRule.ORDERING_RULE_OID))
    {
      return CaseExactStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseIgnoreStringMatchingRule.LOWER_ORDERING_RULE_NAME) ||
             lowerName.equals(CaseIgnoreStringMatchingRule.ORDERING_RULE_OID))
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  GeneralizedTimeMatchingRule.LOWER_ORDERING_RULE_NAME) ||
             lowerName.equals(GeneralizedTimeMatchingRule.ORDERING_RULE_OID))
    {
      return GeneralizedTimeMatchingRule.getInstance();
    }
    else if (lowerName.equals(IntegerMatchingRule.LOWER_ORDERING_RULE_NAME) ||
             lowerName.equals(IntegerMatchingRule.ORDERING_RULE_OID))
    {
      return IntegerMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  NumericStringMatchingRule.LOWER_ORDERING_RULE_NAME) ||
             lowerName.equals(NumericStringMatchingRule.ORDERING_RULE_OID))
    {
      return NumericStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  OctetStringMatchingRule.LOWER_ORDERING_RULE_NAME) ||
             lowerName.equals(OctetStringMatchingRule.ORDERING_RULE_OID))
    {
      return OctetStringMatchingRule.getInstance();
    }
    else
    {
      return getDefaultOrderingMatchingRule();
    }
  }



  /**
   * Retrieves the default matching rule that will be used for ordering matching
   * if no other matching rule is specified or available.  The rule returned
   * will perform case-ignore string matching.
   *
   * @return  The default matching rule that will be used for ordering matching
   *          if no other matching rule is specified or available.
   */
  @NotNull()
  public static MatchingRule getDefaultOrderingMatchingRule()
  {
    return CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Attempts to select the appropriate matching rule to use for substring
   * matching against the specified attribute.  If an appropriate matching rule
   * cannot be determined, then the default substring matching rule will be
   * selected.
   *
   * @param  attrName  The name of the attribute to examine in the provided
   *                   schema.
   * @param  schema    The schema to examine to make the appropriate
   *                   determination.  If this is {@code null}, then the default
   *                   substring matching rule will be selected.
   *
   * @return  The selected matching rule.
   */
  @NotNull()
  public static MatchingRule selectSubstringMatchingRule(
                                  @NotNull final String attrName,
                                  @Nullable final Schema schema)
  {
    return selectSubstringMatchingRule(attrName, null, schema);
  }



  /**
   * Attempts to select the appropriate matching rule to use for substring
   * matching against the specified attribute.  If an appropriate matching rule
   * cannot be determined, then the default substring matching rule will be
   * selected.
   *
   * @param  attrName  The name of the attribute to examine in the provided
   *                   schema.  It may be {@code null} if the matching rule
   *                   should be selected using the matching rule ID.
   * @param  ruleID    The OID of the desired matching rule.  It may be
   *                   {@code null} if the matching rule should be selected only
   *                   using the attribute name.  If a rule ID is provided, then
   *                   it will be the only criteria used to select the matching
   *                   rule.
   * @param  schema    The schema to examine to make the appropriate
   *                   determination.  If this is {@code null} and no rule ID
   *                   was provided, then the default substring matching rule
   *                   will be selected.
   *
   * @return  The selected matching rule.
   */
  @NotNull()
  public static MatchingRule selectSubstringMatchingRule(
                                  @Nullable final String attrName,
                                  @Nullable final String ruleID,
                                  @Nullable final Schema schema)
  {
    if (ruleID != null)
    {
      return selectSubstringMatchingRule(ruleID);
    }

    if ((attrName == null) || (schema == null))
    {
      return getDefaultSubstringMatchingRule();
    }

    final AttributeTypeDefinition attrType = schema.getAttributeType(attrName);
    if (attrType == null)
    {
      return getDefaultSubstringMatchingRule();
    }

    final String mrName = attrType.getSubstringMatchingRule(schema);
    if (mrName != null)
    {
      return selectSubstringMatchingRule(mrName);
    }

    final String emrName = attrType.getEqualityMatchingRule(schema);
    if (emrName != null)
    {
      final MatchingRule mr = selectEqualityMatchingRule(emrName);
      if ((mr != null) && (mr.getSubstringMatchingRuleOID() != null))
      {
        return mr;
      }
    }

    final String syntaxOID = attrType.getBaseSyntaxOID(schema);
    if (syntaxOID != null)
    {
      return selectMatchingRuleForSyntax(syntaxOID);
    }

    return getDefaultSubstringMatchingRule();
  }



  /**
   * Attempts to select the appropriate matching rule to use for substring
   * matching using the specified matching rule.  If an appropriate matching
   * rule cannot be determined, then the default substring matching rule will be
   * selected.
   *
   * @param  ruleID  The name or OID of the desired matching rule.
   *
   * @return  The selected matching rule.
   */
  @NotNull()
  public static MatchingRule selectSubstringMatchingRule(
                                  @NotNull final String ruleID)
  {
    if ((ruleID == null) || ruleID.isEmpty())
    {
      return getDefaultSubstringMatchingRule();
    }

    final String lowerName = StaticUtils.toLowerCase(ruleID);
    if (lowerName.equals(
             CaseExactStringMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
        lowerName.equals(CaseExactStringMatchingRule.SUBSTRING_RULE_OID) ||
        lowerName.equals("caseexactia5substringsmatch"))
    {
      return CaseExactStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseIgnoreListMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
             lowerName.equals(CaseIgnoreListMatchingRule.SUBSTRING_RULE_OID))
    {
      return CaseIgnoreListMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  CaseIgnoreStringMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
             lowerName.equals(
                  CaseIgnoreStringMatchingRule.SUBSTRING_RULE_OID) ||
             lowerName.equals("caseignoreia5substringsmatch") ||
             lowerName.equals("1.3.6.1.4.1.1466.109.114.3"))
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  NumericStringMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
             lowerName.equals(NumericStringMatchingRule.SUBSTRING_RULE_OID))
    {
      return NumericStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  OctetStringMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
             lowerName.equals(OctetStringMatchingRule.SUBSTRING_RULE_OID))
    {
      return OctetStringMatchingRule.getInstance();
    }
    else if (lowerName.equals(
                  TelephoneNumberMatchingRule.LOWER_SUBSTRING_RULE_NAME) ||
             lowerName.equals(TelephoneNumberMatchingRule.SUBSTRING_RULE_OID))
    {
      return TelephoneNumberMatchingRule.getInstance();
    }
    else
    {
      return getDefaultSubstringMatchingRule();
    }
  }



  /**
   * Retrieves the default matching rule that will be used for substring
   * matching if no other matching rule is specified or available.  The rule
   * returned will perform case-ignore string matching.
   *
   * @return  The default matching rule that will be used for substring matching
   *          if no other matching rule is specified or available.
   */
  @NotNull()
  public static MatchingRule getDefaultSubstringMatchingRule()
  {
    return CaseIgnoreStringMatchingRule.getInstance();
  }



  /**
   * Attempts to select the appropriate matching rule for use with the syntax
   * with the specified OID.  If an appropriate matching rule cannot be
   * determined, then the case-ignore string matching rule will be selected.
   *
   * @param  syntaxOID  The OID of the attribute syntax for which to make the
   *                    determination.
   *
   * @return  The selected matching rule.
   */
  @NotNull()
  public static MatchingRule selectMatchingRuleForSyntax(
                                  @NotNull final String syntaxOID)
  {
    if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.7"))
    {
      return BooleanMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.41")) // Postal addr.
    {
      return CaseIgnoreListMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.12") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.34")) // name&optional UID
    {
      return DistinguishedNameMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.24") ||
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.53")) // UTC time
    {
      return GeneralizedTimeMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.27"))
    {
      return IntegerMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.36"))
    {
      return NumericStringMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.4203.1.1.2") || // auth password
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.5") || // binary
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.8") || // certificate
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.9") || // cert list
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.10") || // cert pair
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.28") || // JPEG
         syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.40")) // octet string
    {
      return OctetStringMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.1466.115.121.1.50"))
    {
      return TelephoneNumberMatchingRule.getInstance();
    }
    else if (syntaxOID.equals("1.3.6.1.4.1.30221.2.3.4")) // JSON object exact
    {
      return JSONObjectExactMatchingRule.getInstance();
    }
    else
    {
      return CaseIgnoreStringMatchingRule.getInstance();
    }
  }
}
