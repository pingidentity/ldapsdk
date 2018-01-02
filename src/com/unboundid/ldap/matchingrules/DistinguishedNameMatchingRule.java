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
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.matchingrules.MatchingRuleMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides an implementation of a matching rule that performs
 * equality comparisons against values that should be distinguished names.
 * Substring and ordering matching are not supported.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DistinguishedNameMatchingRule
       extends MatchingRule
{
  /**
   * The singleton instance that will be returned from the {@code getInstance}
   * method.
   */
  private static final DistinguishedNameMatchingRule INSTANCE =
       new DistinguishedNameMatchingRule();



  /**
   * The name for the distinguishedNameMatch equality matching rule.
   */
  public static final String EQUALITY_RULE_NAME = "distinguishedNameMatch";



  /**
   * The name for the distinguishedNameMatch equality matching rule, formatted
   * in all lowercase characters.
   */
  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);



  /**
   * The OID for the distinguishedNameMatch equality matching rule.
   */
  public static final String EQUALITY_RULE_OID = "2.5.13.1";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2617356571703597868L;



  /**
   * Creates a new instance of this distinguished name matching rule.
   */
  public DistinguishedNameMatchingRule()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a singleton instance of this matching rule.
   *
   * @return  A singleton instance of this matching rule.
   */
  public static DistinguishedNameMatchingRule getInstance()
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
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getOrderingMatchingRuleOID()
  {
    return null;
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
    final DN dn1;
    try
    {
      dn1 = new DN(value1.stringValue());
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                              le.getMessage(), le);
    }

    final DN dn2;
    try
    {
      dn2 = new DN(value2.stringValue());
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                              le.getMessage(), le);
    }

    return dn1.equals(dn2);
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

    final DN assertionValueDN;
    try
    {
      assertionValueDN = new DN(assertionValue.stringValue());
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           le.getMessage(), le);
    }

    for (final ASN1OctetString attributeValue : attributeValues)
    {
      try
      {
        if (assertionValueDN.equals(new DN(attributeValue.stringValue())))
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
                            ERR_DN_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                            ERR_DN_ORDERING_MATCHING_NOT_SUPPORTED.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
         throws LDAPException
  {
    try
    {
      final DN dn = new DN(value.stringValue());
      return new ASN1OctetString(dn.toNormalizedString());
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                              le.getMessage(), le);
    }
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
                            ERR_DN_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }
}
