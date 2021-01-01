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



import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.matchingrules.MatchingRuleMessages.*;



/**
 * This class provides an implementation of a matching rule that performs
 * equality and ordering comparisons against values that should be timestamps
 * in the generalized time syntax.  Substring matching is not supported.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GeneralizedTimeMatchingRule
       extends MatchingRule
{
  /**
   * The singleton instance that will be returned from the {@code getInstance}
   * method.
   */
  @NotNull private static final GeneralizedTimeMatchingRule INSTANCE =
       new GeneralizedTimeMatchingRule();



  /**
   * The date format that will be used for formatting generalized time values,
   * assuming that the associated formatter is using the UTC time zone.
   */
  @NotNull private static final String GENERALIZED_TIME_DATE_FORMAT =
       "yyyyMMddHHmmss.SSS'Z'";



  /**
   * A reference to the "UTC" time zone.
   */
  @NotNull private static final TimeZone UTC_TIME_ZONE =
       TimeZone.getTimeZone("UTC");



  /**
   * The name for the generalizedTimeMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_NAME =
       "generalizedTimeMatch";



  /**
   * The name for the generalizedTimeMatch equality matching rule, formatted in
   * all lowercase characters.
   */
  @NotNull static final String LOWER_EQUALITY_RULE_NAME =
       StaticUtils.toLowerCase(EQUALITY_RULE_NAME);



  /**
   * The OID for the generalizedTimeMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_OID = "2.5.13.27";



  /**
   * The name for the generalizedTimeOrderingMatch ordering matching rule.
   */
  @NotNull public static final String ORDERING_RULE_NAME =
       "generalizedTimeOrderingMatch";



  /**
   * The name for the generalizedTimeOrderingMatch ordering matching rule,
   * formatted in all lowercase characters.
   */
  @NotNull static final String LOWER_ORDERING_RULE_NAME =
       StaticUtils.toLowerCase(ORDERING_RULE_NAME);



  /**
   * The OID for the generalizedTimeOrderingMatch ordering matching rule.
   */
  @NotNull public static final String ORDERING_RULE_OID = "2.5.13.28";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6317451154598148593L;



  // The thread-local date formatter for this class.
  @NotNull private static final ThreadLocal<SimpleDateFormat> dateFormat =
       new ThreadLocal<>();



  /**
   * Creates a new instance of this generalized time matching rule.
   */
  public GeneralizedTimeMatchingRule()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a singleton instance of this matching rule.
   *
   * @return  A singleton instance of this matching rule.
   */
  @NotNull()
  public static GeneralizedTimeMatchingRule getInstance()
  {
    return INSTANCE;
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
  @NotNull()
  public String getOrderingMatchingRuleName()
  {
    return ORDERING_RULE_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getOrderingMatchingRuleOID()
  {
    return ORDERING_RULE_OID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getSubstringMatchingRuleName()
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getSubstringMatchingRuleOID()
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valuesMatch(@NotNull final ASN1OctetString value1,
                             @NotNull final ASN1OctetString value2)
         throws LDAPException
  {
    final Date d1;
    try
    {
      d1 = StaticUtils.decodeGeneralizedTime(value1.stringValue());
    }
    catch (final ParseException pe)
    {
      Debug.debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    final Date d2;
    try
    {
      d2 = StaticUtils.decodeGeneralizedTime(value2.stringValue());
    }
    catch (final ParseException pe)
    {
      Debug.debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    return d1.equals(d2);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean matchesAnyValue(@NotNull final ASN1OctetString assertionValue,
                      @NotNull final ASN1OctetString[] attributeValues)
         throws LDAPException
  {
    if ((assertionValue == null) || (attributeValues == null) ||
        (attributeValues.length == 0))
    {
      return false;
    }

    final Date assertionValueDate;
    try
    {
      assertionValueDate =
           StaticUtils.decodeGeneralizedTime(assertionValue.stringValue());
    }
    catch (final ParseException pe)
    {
      Debug.debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    for (final ASN1OctetString attributeValue : attributeValues)
    {
      try
      {
        if (assertionValueDate.equals(
             StaticUtils.decodeGeneralizedTime(attributeValue.stringValue())))
        {
          return true;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean matchesSubstring(@NotNull final ASN1OctetString value,
                      @Nullable final ASN1OctetString subInitial,
                      @Nullable final ASN1OctetString[] subAny,
                      @Nullable final ASN1OctetString subFinal)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_GENERALIZED_TIME_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int compareValues(@NotNull final ASN1OctetString value1,
                           @NotNull final ASN1OctetString value2)
         throws LDAPException
  {
    final Date d1;
    try
    {
      d1 = StaticUtils.decodeGeneralizedTime(value1.stringValue());
    }
    catch (final ParseException pe)
    {
      Debug.debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    final Date d2;
    try
    {
      d2 = StaticUtils.decodeGeneralizedTime(value2.stringValue());
    }
    catch (final ParseException pe)
    {
      Debug.debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    return d1.compareTo(d2);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1OctetString normalize(@NotNull final ASN1OctetString value)
         throws LDAPException
  {
    final Date d;
    try
    {
      d = StaticUtils.decodeGeneralizedTime(value.stringValue());
    }
    catch (final ParseException pe)
    {
      Debug.debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    SimpleDateFormat f = dateFormat.get();
    if (f == null)
    {
      f = new SimpleDateFormat(GENERALIZED_TIME_DATE_FORMAT);
      f.setTimeZone(UTC_TIME_ZONE);
      dateFormat.set(f);
    }

    return new ASN1OctetString(f.format(d));
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
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_GENERALIZED_TIME_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }
}
