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



import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.matchingrules.MatchingRuleMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



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
  private static final GeneralizedTimeMatchingRule INSTANCE =
       new GeneralizedTimeMatchingRule();



  /**
   * The date format that will be used for formatting generalized time values,
   * assuming that the associated formatter is using the UTC time zone.
   */
  private static final String GENERALIZED_TIME_DATE_FORMAT =
       "yyyyMMddHHmmss.SSS'Z'";



  /**
   * A reference to the "UTC" time zone.
   */
  private static final TimeZone UTC_TIME_ZONE = TimeZone.getTimeZone("UTC");



  /**
   * The name for the generalizedTimeMatch equality matching rule.
   */
  public static final String EQUALITY_RULE_NAME = "generalizedTimeMatch";



  /**
   * The name for the generalizedTimeMatch equality matching rule, formatted in
   * all lowercase characters.
   */
  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);



  /**
   * The OID for the generalizedTimeMatch equality matching rule.
   */
  public static final String EQUALITY_RULE_OID = "2.5.13.27";



  /**
   * The name for the generalizedTimeOrderingMatch ordering matching rule.
   */
  public static final String ORDERING_RULE_NAME =
       "generalizedTimeOrderingMatch";



  /**
   * The name for the generalizedTimeOrderingMatch ordering matching rule,
   * formatted in all lowercase characters.
   */
  static final String LOWER_ORDERING_RULE_NAME =
       toLowerCase(ORDERING_RULE_NAME);



  /**
   * The OID for the generalizedTimeOrderingMatch ordering matching rule.
   */
  public static final String ORDERING_RULE_OID = "2.5.13.28";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6317451154598148593L;



  // The thread-local date formatter for this class.
  private static final ThreadLocal<SimpleDateFormat> dateFormat =
       new ThreadLocal<SimpleDateFormat>();



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
  public static GeneralizedTimeMatchingRule getInstance()
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
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSubstringMatchingRuleOID()
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valuesMatch(final ASN1OctetString value1,
                             final ASN1OctetString value2)
         throws LDAPException
  {
    final Date d1;
    try
    {
      d1 = decodeGeneralizedTime(value1.stringValue());
    }
    catch (final ParseException pe)
    {
      debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    final Date d2;
    try
    {
      d2 = decodeGeneralizedTime(value2.stringValue());
    }
    catch (final ParseException pe)
    {
      debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    return d1.equals(d2);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean matchesAnyValue(final ASN1OctetString assertionValue,
                                 final ASN1OctetString[] attributeValues)
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
      assertionValueDate = decodeGeneralizedTime(assertionValue.stringValue());
    }
    catch (final ParseException pe)
    {
      debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    for (final ASN1OctetString attributeValue : attributeValues)
    {
      try
      {
        if (assertionValueDate.equals(
             decodeGeneralizedTime(attributeValue.stringValue())))
        {
          return true;
        }
      }
      catch (final Exception e)
      {
        debugException(e);
      }
    }

    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean matchesSubstring(final ASN1OctetString value,
                                  final ASN1OctetString subInitial,
                                  final ASN1OctetString[] subAny,
                                  final ASN1OctetString subFinal)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_GENERALIZED_TIME_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
         throws LDAPException
  {
    final Date d1;
    try
    {
      d1 = decodeGeneralizedTime(value1.stringValue());
    }
    catch (final ParseException pe)
    {
      debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    final Date d2;
    try
    {
      d2 = decodeGeneralizedTime(value2.stringValue());
    }
    catch (final ParseException pe)
    {
      debugException(pe);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_GENERALIZED_TIME_INVALID_VALUE.get(pe.getMessage()), pe);
    }

    return d1.compareTo(d2);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException
  {
    final Date d;
    try
    {
      d = decodeGeneralizedTime(value.stringValue());
    }
    catch (final ParseException pe)
    {
      debugException(pe);
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
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_GENERALIZED_TIME_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }
}
