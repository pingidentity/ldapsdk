/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class defines an API that should be implemented by classes which may
 * represent a way to pare down the changelog entries that should be returned
 * (e.g., so that they only include changes to a particular attribute or set of
 * attributes) when using the {@link GetChangelogBatchExtendedRequest}.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class ChangelogBatchChangeSelectionCriteria
{
  /**
   * The outer BER type that should be used for encoded elements that represent
   * a get changelog batch selection criteria value.
   */
  static final byte TYPE_SELECTION_CRITERIA = (byte) 0xA7;



  /**
   * Encodes this changelog batch change selection criteria value to an ASN.1
   * element suitable for inclusion in the get changelog batch extended request.
   *
   * @return  An ASN.1 element containing the encoded representation of this
   *          changelog batch change selection criteria value.
   */
  @NotNull()
  public final ASN1Element encode()
  {
    return new ASN1Element(TYPE_SELECTION_CRITERIA,
         encodeInnerElement().encode());
  }



  /**
   * Encodes the inner element for this changelog batch change selection
   * criteria to an ASN.1 element.
   *
   * @return  The encoded representation of the inner element to include in the
   *          encoded representation of the changelog batch change selection
   *          criteria element.
   */
  @NotNull()
  protected abstract ASN1Element encodeInnerElement();



  /**
   * Decodes the provided ASN.1 element as a changelog batch change selection
   * criteria value.
   *
   * @param  element  The ASN.1 element to be decoded.  It must not be
   *                  {@code null}.
   *
   * @return  The decoded changelog batch change selection criteria value.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a changelog batch starting point.
   */
  @NotNull()
  public static ChangelogBatchChangeSelectionCriteria decode(
                     @NotNull final ASN1Element element)
         throws LDAPException
  {
    Validator.ensureNotNull(element);

    // The value of the element is itself an ASN.1 element, and we need to use
    // its BER type to figure out what type of element it is.
    final ASN1Element innerElement;
    try
    {
      innerElement = ASN1Element.decode(element.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CLBATCH_CHANGE_SELECTION_CRITERIA_DECODE_INNER_FAILURE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    switch (innerElement.getType())
    {
      case AnyAttributesChangeSelectionCriteria.
           TYPE_SELECTION_CRITERIA_ANY_ATTRIBUTES:
        return AnyAttributesChangeSelectionCriteria.decodeInnerElement(
             innerElement);
      case AllAttributesChangeSelectionCriteria.
           TYPE_SELECTION_CRITERIA_ALL_ATTRIBUTES:
        return AllAttributesChangeSelectionCriteria.decodeInnerElement(
             innerElement);
      case IgnoreAttributesChangeSelectionCriteria.
           TYPE_SELECTION_CRITERIA_IGNORE_ATTRIBUTES:
        return IgnoreAttributesChangeSelectionCriteria.decodeInnerElement(
             innerElement);
      case NotificationDestinationChangeSelectionCriteria.
           TYPE_SELECTION_CRITERIA_NOTIFICATION_DESTINATION:
        return NotificationDestinationChangeSelectionCriteria.
             decodeInnerElement(innerElement);
      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CLBATCH_CHANGE_SELECTION_CRITERIA_UNKNOWN_TYPE.get(
                  StaticUtils.toHex(innerElement.getType())));
    }
  }



  /**
   * Retrieves a string representation of this changelog batch change selection
   * criteria value.
   *
   * @return  A string representation of this changelog batch change selection
   *          criteria value.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this changelog batch change selection
   * criteria value to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public abstract void toString(@NotNull StringBuilder buffer);
}
