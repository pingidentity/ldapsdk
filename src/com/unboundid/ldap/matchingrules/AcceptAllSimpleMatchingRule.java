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
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.Debug;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a common matching rule framework that may be extended by
 * matching rule implementations in which equality, ordering, and substring
 * matching can all be made based on byte-for-byte comparisons of the normalized
 * value, and any value is acceptable.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class AcceptAllSimpleMatchingRule
       extends SimpleMatchingRule
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7450007924568660003L;



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valuesMatch(@NotNull final ASN1OctetString value1,
                             @NotNull final ASN1OctetString value2)
  {
    return normalize(value1).equalsIgnoreType(normalize(value2));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean matchesAnyValue(@NotNull final ASN1OctetString assertionValue,
                      @NotNull final ASN1OctetString[] attributeValues)
  {
    if ((assertionValue == null) || (attributeValues == null) ||
        (attributeValues.length == 0))
    {
      return false;
    }

    final ASN1OctetString normalizedAssertionValue = normalize(assertionValue);

    for (final ASN1OctetString attributeValue : attributeValues)
    {
      if (normalizedAssertionValue.equalsIgnoreType(normalize(attributeValue)))
      {
        return true;
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
  {
    try
    {
      return super.matchesSubstring(value, subInitial, subAny, subFinal);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      // This should never happen, as the only reason the superclass version of
      // this method will throw an exception is if an exception is thrown by
      // normalize or normalizeSubstring.
      return false;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int compareValues(@NotNull final ASN1OctetString value1,
                           @NotNull final ASN1OctetString value2)
  {
    try
    {
      return super.compareValues(value1, value2);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      // This should never happen, as the only reason the superclass version of
      // this method will throw an exception is if an exception is thrown by
      // normalize or normalizeSubstring.
      return 0;
    }
  }



  /**
   * {@inheritDoc}  This variant of the {@code normalize} method is not allowed
   * to throw exceptions.
   */
  @Override()
  @NotNull()
  public abstract ASN1OctetString normalize(@NotNull ASN1OctetString value);



  /**
   * {@inheritDoc}  This variant of the {@code normalizeSubstring} method is not
   * allowed to throw exceptions.
   */
  @Override()
  @NotNull()
  public abstract ASN1OctetString normalizeSubstring(
                                       @NotNull ASN1OctetString value,
                                       byte substringType);
}
