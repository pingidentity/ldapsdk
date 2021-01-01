/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a joined entry, which is a read-only representation of an
 * entry that has been joined with a search result entry using the LDAP join
 * control.  See the class-level documentation for the
 * {@link JoinRequestControl} class for additional information and an example
 * demonstrating its use.
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
 * <BR>
 * Joined entries are encoded as follows:
 * <PRE>
 *   JoinedEntry ::= SEQUENCE {
 *        objectName            LDAPDN,
 *        attributes            PartialAttributeList,
 *        nestedJoinResults     SEQUENCE OF JoinedEntry OPTIONAL }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JoinedEntry
       extends ReadOnlyEntry
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6519864521813773703L;



  // The list of nested join results for this joined entry.
  @NotNull private final List<JoinedEntry> nestedJoinResults;



  /**
   * Creates a new joined entry with the specified DN, attributes, and nested
   * join results.
   *
   * @param  entry              The entry containing the DN and attributes to
   *                            use for this joined entry.  It must not be
   *                            {@code null}.
   * @param  nestedJoinResults  A list of nested join results for this joined
   *                            entry.  It may be {@code null} or empty if there
   *                            are no nested join results.
   */
  public JoinedEntry(@NotNull final Entry entry,
                     @Nullable final List<JoinedEntry> nestedJoinResults)
  {
    this(entry.getDN(), entry.getAttributes(), nestedJoinResults);
  }



  /**
   * Creates a new joined entry with the specified DN, attributes, and nested
   * join results.
   *
   * @param  dn                 The DN for this joined entry.  It must not be
   *                            {@code null}.
   * @param  attributes         The set of attributes for this joined entry.  It
   *                            must not be {@code null}.
   * @param  nestedJoinResults  A list of nested join results for this joined
   *                            entry.  It may be {@code null} or empty if there
   *                            are no nested join results.
   */
  public JoinedEntry(@NotNull final String dn,
                     @NotNull final Collection<Attribute> attributes,
                     @Nullable final List<JoinedEntry> nestedJoinResults)
  {
    super(dn, attributes);

    if (nestedJoinResults == null)
    {
      this.nestedJoinResults = Collections.emptyList();
    }
    else
    {
      this.nestedJoinResults = Collections.unmodifiableList(nestedJoinResults);
    }
  }



  /**
   * Encodes this joined entry to an ASN.1 element.
   *
   * @return  An ASN.1 element containing the encoded representation of this
   *          joined entry.
   */
  @NotNull()
  ASN1Element encode()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(3);

    elements.add(new ASN1OctetString(getDN()));

    final ArrayList<ASN1Element> attrElements = new ArrayList<>(20);
    for (final Attribute a : getAttributes())
    {
      attrElements.add(a.encode());
    }
    elements.add(new ASN1Sequence(attrElements));

    if (! nestedJoinResults.isEmpty())
    {
      final ArrayList<ASN1Element> nestedElements =
           new ArrayList<>(nestedJoinResults.size());
      for (final JoinedEntry je : nestedJoinResults)
      {
        nestedElements.add(je.encode());
      }
      elements.add(new ASN1Sequence(nestedElements));
    }

    return new ASN1Sequence(elements);
  }



  /**
   * Decodes the provided ASN.1 element as a joined entry.
   *
   * @param  element  The ASN.1 element to decode as a joined entry.
   *
   * @return  The decoded joined entry.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided ASN.1 element as a joined entry.
   */
  @NotNull()
  static JoinedEntry decode(@NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String dn =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      final ASN1Element[] attrElements =
           ASN1Sequence.decodeAsSequence(elements[1]).elements();
      final ArrayList<Attribute> attrs = new ArrayList<>(attrElements.length);
      for (final ASN1Element e : attrElements)
      {
        attrs.add(Attribute.decode(ASN1Sequence.decodeAsSequence(e)));
      }

      final ArrayList<JoinedEntry> nestedJoinResults;
      if (elements.length == 3)
      {
        final ASN1Element[] nestedElements =
             ASN1Sequence.decodeAsSequence(elements[2]).elements();
        nestedJoinResults = new ArrayList<>(nestedElements.length);
        for (final ASN1Element e : nestedElements)
        {
          nestedJoinResults.add(decode(e));
        }
      }
      else
      {
        nestedJoinResults = new ArrayList<>(0);
      }

      return new JoinedEntry(dn, attrs, nestedJoinResults);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_JOINED_ENTRY_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the list of nested join results for this joined entry.
   *
   * @return  The list of nested join results for this joined entry, or an
   *          empty list if there are none.
   */
  @NotNull()
  public List<JoinedEntry> getNestedJoinResults()
  {
    return nestedJoinResults;
  }



  /**
   * Appends a string representation of this joined entry to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("JoinedEntry(dn='");
    buffer.append(getDN());
    buffer.append("', attributes={");

    final Iterator<Attribute> attrIterator = getAttributes().iterator();
    while (attrIterator.hasNext())
    {
      attrIterator.next().toString(buffer);
      if (attrIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, nestedJoinResults={");

    final Iterator<JoinedEntry> entryIterator = nestedJoinResults.iterator();
    while (entryIterator.hasNext())
    {
      entryIterator.next().toString(buffer);
      if (entryIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
