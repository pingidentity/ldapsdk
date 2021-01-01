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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.DN;
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
  @NotNull private static final DistinguishedNameMatchingRule INSTANCE =
       new DistinguishedNameMatchingRule();



  /**
   * The name for the distinguishedNameMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_NAME =
       "distinguishedNameMatch";



  /**
   * The name for the distinguishedNameMatch equality matching rule, formatted
   * in all lowercase characters.
   */
  @NotNull static final String LOWER_EQUALITY_RULE_NAME =
       StaticUtils.toLowerCase(EQUALITY_RULE_NAME);



  /**
   * The OID for the distinguishedNameMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_OID = "2.5.13.1";



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
  @NotNull()
  public static DistinguishedNameMatchingRule getInstance()
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
    final DN dn1;
    try
    {
      dn1 = new DN(value1.stringValue());
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
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
      Debug.debugException(le);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                              le.getMessage(), le);
    }

    return dn1.equals(dn2);
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

    final DN assertionValueDN;
    try
    {
      assertionValueDN = new DN(assertionValue.stringValue());
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
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
                            ERR_DN_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
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
                            ERR_DN_ORDERING_MATCHING_NOT_SUPPORTED.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1OctetString normalize(@NotNull final ASN1OctetString value)
         throws LDAPException
  {
    try
    {
      final DN dn = new DN(value.stringValue());
      return new ASN1OctetString(dn.toNormalizedString());
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                              le.getMessage(), le);
    }
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
                            ERR_DN_SUBSTRING_MATCHING_NOT_SUPPORTED.get());
  }
}
