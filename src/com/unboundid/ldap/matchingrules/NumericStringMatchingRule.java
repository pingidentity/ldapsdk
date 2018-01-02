/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.matchingrules.MatchingRuleMessages.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides an implementation of a matching rule that allows strings
 * consisting of numeric digits and spaces.  Spaces will be considered
 * insignificant for matching purposes.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class NumericStringMatchingRule
       extends SimpleMatchingRule
{
  /**
   * The singleton instance that will be returned from the {@code getInstance}
   * method.
   */
  private static final NumericStringMatchingRule INSTANCE =
       new NumericStringMatchingRule();



  /**
   * The name for the numericStringMatch equality matching rule.
   */
  public static final String EQUALITY_RULE_NAME = "numericStringMatch";



  /**
   * The name for the numericStringMatch equality matching rule, formatted in
   * all lowercase characters.
   */
  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);



  /**
   * The OID for the numericStringMatch equality matching rule.
   */
  public static final String EQUALITY_RULE_OID = "2.5.13.8";



  /**
   * The name for the numericStringOrderingMatch ordering matching rule.
   */
  public static final String ORDERING_RULE_NAME = "numericStringOrderingMatch";



  /**
   * The name for the numericStringOrderingMatch ordering matching rule,
   * formatted in all lowercase characters.
   */
  static final String LOWER_ORDERING_RULE_NAME =
       toLowerCase(ORDERING_RULE_NAME);



  /**
   * The OID for the numericStringOrderingMatch ordering matching rule.
   */
  public static final String ORDERING_RULE_OID = "2.5.13.9";



  /**
   * The name for the numericStringSubstringsMatch substring matching rule.
   */
  public static final String SUBSTRING_RULE_NAME =
       "numericStringSubstringsMatch";



  /**
   * The name for the numericStringSubstringsMatch substring matching rule,
   * formatted in all lowercase characters.
   */
  static final String LOWER_SUBSTRING_RULE_NAME =
       toLowerCase(SUBSTRING_RULE_NAME);



  /**
   * The OID for the numericStringSubstringsMatch substring matching rule.
   */
  public static final String SUBSTRING_RULE_OID = "2.5.13.10";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -898484312052746321L;



  /**
   * Creates a new instance of this numeric string matching rule.
   */
  public NumericStringMatchingRule()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a singleton instance of this matching rule.
   *
   * @return  A singleton instance of this matching rule.
   */
  public static NumericStringMatchingRule getInstance()
  {
    return INSTANCE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getEqualityMatchingRuleName()
  {
    return EQUALITY_RULE_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getEqualityMatchingRuleOID()
  {
    return EQUALITY_RULE_OID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getOrderingMatchingRuleName()
  {
    return ORDERING_RULE_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getOrderingMatchingRuleOID()
  {
    return ORDERING_RULE_OID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSubstringMatchingRuleName()
  {
    return SUBSTRING_RULE_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSubstringMatchingRuleOID()
  {
    return SUBSTRING_RULE_OID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException
  {
    // The value may already be normalized, so optimize behavior for that
    // possibility.
    int numSpaces = 0;
    final byte[] valueBytes = value.getValue();
    for (int i=0; i < valueBytes.length; i++)
    {
      if (valueBytes[i] == ' ')
      {
        numSpaces++;
      }
      else if ((valueBytes[i] < '0') || (valueBytes[i] > '9'))
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                                ERR_NUMERIC_STRING_INVALID_CHARACTER.get(i));
      }
    }

    if (numSpaces == 0)
    {
      return value;
    }

    int pos = 0;
    final byte[] returnBytes = new byte[valueBytes.length-numSpaces];
    for (final byte b : valueBytes)
    {
      if (b != ' ')
      {
        returnBytes[pos++] = b;
      }
    }

    return new ASN1OctetString(returnBytes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
         throws LDAPException
  {
    return normalize(value);
  }
}
