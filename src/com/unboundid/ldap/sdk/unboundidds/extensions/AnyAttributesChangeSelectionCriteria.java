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



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of a get changelog batch change
 * selection criteria value that indicates that the server should only return
 * changes which target one or more of the specified attributes.  The changes
 * may target other attributes as well, but at least one of the associated
 * attributes must be included in the change.
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
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AnyAttributesChangeSelectionCriteria
       extends ChangelogBatchChangeSelectionCriteria
{
  /**
   * The inner BER type that should be used for encoded elements that represent
   * an any attributes get changelog batch selection criteria value.
   */
  static final byte TYPE_SELECTION_CRITERIA_ANY_ATTRIBUTES = (byte) 0xA1;



  // The names of the target attributes.
  @NotNull private final List<String> attributeNames;



  /**
   * Creates a new any attributes change selection criteria value with the
   * provided set of attribute names.
   *
   * @param  attributeNames  The names of the target attributes for changes that
   *                         should be retrieved.  It must not be {@code null}
   *                         or empty.
   */
  public AnyAttributesChangeSelectionCriteria(
              @NotNull final String... attributeNames)
  {
    this(StaticUtils.toList(attributeNames));
  }



  /**
   * Creates a new any attributes change selection criteria value with the
   * provided set of attribute names.
   *
   * @param  attributeNames  The names of the target attributes for changes that
   *                         should be retrieved.  It must not be {@code null}
   *                         or empty.
   */
  public AnyAttributesChangeSelectionCriteria(
              @NotNull final Collection<String> attributeNames)
  {
    Validator.ensureNotNull(attributeNames);
    Validator.ensureFalse(attributeNames.isEmpty());

    this.attributeNames =
         Collections.unmodifiableList(new ArrayList<>(attributeNames));
  }



  /**
   * Decodes the provided ASN.1 element, which is the inner element of a
   * changelog batch change selection criteria element, as an any attributes
   * change selection criteria value.
   *
   * @param  innerElement  The inner element of a changelog batch change
   *                       selection criteria element to be decoded.
   *
   * @return  The decoded any attributes change selection criteria value.
   *
   * @throws  LDAPException  If a problem is encountered while trying to decode
   *                         the provided element as the inner element of an any
   *                         attributes change selection criteria value.
   */
  @NotNull()
  static AnyAttributesChangeSelectionCriteria decodeInnerElement(
              @NotNull final ASN1Element innerElement)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] attrElements =
           ASN1Sequence.decodeAsSequence(innerElement).elements();
      final ArrayList<String> attrNames = new ArrayList<>(attrElements.length);
      for (final ASN1Element e : attrElements)
      {
        attrNames.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
      }

      return new AnyAttributesChangeSelectionCriteria(attrNames);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ANY_ATTRS_CHANGE_SELECTION_CRITERIA_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the names of the target attributes for changes that should be
   * retrieved.
   *
   * @return  The names of the target attributes for changes that should be
   *          retrieved.
   */
  @NotNull()
  public List<String> getAttributeNames()
  {
    return attributeNames;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encodeInnerElement()
  {
    final ArrayList<ASN1Element> elements =
         new ArrayList<>(attributeNames.size());
    for (final String s : attributeNames)
    {
      elements.add(new ASN1OctetString(s));
    }

    return new ASN1Sequence(TYPE_SELECTION_CRITERIA_ANY_ATTRIBUTES, elements);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AnyAttributesChangeSelectionCriteria(attributeNames={");

    final Iterator<String> iterator = attributeNames.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next());
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append("})");
  }
}
