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
package com.unboundid.ldap.sdk.controls;



import java.io.Serializable;
import java.util.ArrayList;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides a data structure for representing a sort key that is to
 * be used in conjunction with the {@link ServerSideSortRequestControl} for
 * requesting that the server sort the results before returning them to the
 * client.
 * <BR><BR>
 * A sort key includes the following elements:
 * <UL>
 *   <LI>The name of the attribute for which sorting is to be performed.</LI>
 *   <LI>A {@code reverseOrder} flag that indicates whether the results should
 *       be sorted in ascending order (if the value is {@code false}) or
 *       descending order (if the value is {@code true}).</LI>
 *   <LI>An optional matching rule ID, which specifies the ordering matching
 *       rule that should be used to perform the sorting.  If this is not
 *       provided, then the default ordering matching rule for the specified
 *       attribute will be used.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SortKey
       implements Serializable
{
  /**
   * The BER type that should be used for the matching rule ID element.
   */
  private static final byte TYPE_MATCHING_RULE_ID = (byte) 0x80;



  /**
   * The BER type that should be used for the reverse order element.
   */
  private static final byte TYPE_REVERSE_ORDER = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8631224188301402858L;



  // Indicates whether the sort should be performed in reverse order.
  private final boolean reverseOrder;

  // The attribute name for this sort key.
  @NotNull private final String attributeName;

  // The matching rule ID for this sort key.
  @Nullable private final String matchingRuleID;



  /**
   * Creates a new sort key with the specified attribute name.  It will use the
   * default ordering matching rule associated with that attribute, and it will
   * not use reverse order.
   *
   * @param  attributeName  The attribute name for this sort key.  It must not
   *                        be {@code null}.
   */
  public SortKey(@NotNull final String attributeName)
  {
    this(attributeName, null, false);
  }



  /**
   * Creates a new sort key with the specified attribute name.  It will use the
   * default ordering matching rule associated with that attribute.
   *
   * @param  attributeName  The attribute name for this sort key.  It must not
   *                        be {@code null}.
   * @param  reverseOrder   Indicates whether the sort should be performed in
   *                        reverse order.
   */
  public SortKey(@NotNull final String attributeName,
                 final boolean reverseOrder)
  {
    this(attributeName, null, reverseOrder);
  }



  /**
   * Creates a new sort key with the provided information.
   *
   * @param  attributeName   The attribute name for this sort key.  It must not
   *                         be {@code null}.
   * @param  matchingRuleID  The name or OID of the ordering matching rule that
   *                         should be used to perform the sort.  It may be
   *                         {@code null} if the default ordering matching rule
   *                         for the specified attribute is to be used.
   * @param  reverseOrder    Indicates whether the sort should be performed in
   *                         reverse order.
   */
  public SortKey(@NotNull final String attributeName,
                 @Nullable final String matchingRuleID,
                 final boolean reverseOrder)
  {
    Validator.ensureNotNull(attributeName);

    this.attributeName  = attributeName;
    this.matchingRuleID = matchingRuleID;
    this.reverseOrder   = reverseOrder;
  }



  /**
   * Retrieves the attribute name for this sort key.
   *
   * @return  The attribute name for this sort key.
   */
  @NotNull()
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * Retrieves the name or OID of the ordering matching rule that should be used
   * to perform the sort, if defined.
   *
   * @return  The name or OID of the ordering matching rule that should be used
   *          to perform the sort, or {@code null} if the sort should use the
   *          default ordering matching rule associated with the specified
   *          attribute.
   */
  @Nullable()
  public String getMatchingRuleID()
  {
    return matchingRuleID;
  }



  /**
   * Indicates whether the sort should be performed in reverse order.
   *
   * @return  {@code true} if the sort should be performed in reverse order, or
   *          {@code false} if it should be performed in the standard order for
   *          the associated ordering matching rule.
   */
  public boolean reverseOrder()
  {
    return reverseOrder;
  }



  /**
   * Encodes this sort key into an ASN.1 sequence suitable for use in the
   * server-side sort control.
   *
   * @return  An ASN.1 sequence containing the encoded representation of this
   *          sort key.
   */
  @NotNull()
  ASN1Sequence encode()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(3);
    elements.add(new ASN1OctetString(attributeName));

    if (matchingRuleID != null)
    {
      elements.add(new ASN1OctetString(TYPE_MATCHING_RULE_ID, matchingRuleID));
    }

    if (reverseOrder)
    {
      elements.add(new ASN1Boolean(TYPE_REVERSE_ORDER, reverseOrder));
    }

    return new ASN1Sequence(elements);
  }



  /**
   * Decodes the provided ASN.1 element as a sort key.
   *
   * @param  element  The ASN.1 element to decode as a sort key.
   *
   * @return  The decoded sort key.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a sort key.
   */
  @NotNull()
  public static SortKey decode(@NotNull final ASN1Element element)
         throws LDAPException
  {
    final ASN1Element[] elements;
    try
    {
      elements = ASN1Sequence.decodeAsSequence(element).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SORT_KEY_NOT_SEQUENCE.get(e), e);
    }

    if ((elements.length < 1) || (elements.length > 3))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SORT_KEY_INVALID_ELEMENT_COUNT.get(elements.length));
    }

    boolean reverseOrder   = false;
    String  matchingRuleID = null;
    final String  attributeName  =
         ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
    for (int i=1; i < elements.length; i++)
    {
      switch (elements[i].getType())
      {
        case TYPE_MATCHING_RULE_ID:
          matchingRuleID =
               ASN1OctetString.decodeAsOctetString(elements[i]).stringValue();
          break;

        case TYPE_REVERSE_ORDER:
          try
          {
            reverseOrder =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_SORT_KEY_REVERSE_NOT_BOOLEAN.get(e), e);
          }
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_SORT_KEY_ELEMENT_INVALID_TYPE.get(
                    StaticUtils.toHex(elements[i].getType())));
      }
    }

    return new SortKey(attributeName, matchingRuleID, reverseOrder);
  }



  /**
   * Retrieves a string representation of this sort key.
   *
   * @return  A string representation of this sort key.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this sort key to the provided buffer.
   *
   * @param  buffer  The buffer to which to append a string representation of
   *                 this sort key.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SortKey(attributeName=");
    buffer.append(attributeName);

    if (matchingRuleID != null)
    {
      buffer.append(", matchingRuleID=");
      buffer.append(matchingRuleID);
    }

    buffer.append(", reverseOrder=");
    buffer.append(reverseOrder);
    buffer.append(')');
  }
}
