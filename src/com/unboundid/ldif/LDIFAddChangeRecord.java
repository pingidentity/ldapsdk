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
package com.unboundid.ldif;



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines an LDIF add change record, which can be used to represent
 * an LDAP add request.  See the documentation for the {@link LDIFChangeRecord}
 * class for an example demonstrating the process for interacting with LDIF
 * change records.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDIFAddChangeRecord
       extends LDIFChangeRecord
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4722916031463878423L;



  // The set of attributes for this add change record.
  @NotNull private final Attribute[] attributes;



  /**
   * Creates a new LDIF add change record with the provided DN and attributes.
   *
   * @param  dn          The DN for this LDIF add change record.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes for this LDIF add change record.
   *                     It must not be {@code null} or empty.
   */
  public LDIFAddChangeRecord(@NotNull final String dn,
                             @NotNull final Attribute... attributes)
  {
    this(dn, attributes, null);
  }



  /**
   * Creates a new LDIF add change record with the provided DN and attributes.
   *
   * @param  dn          The DN for this LDIF add change record.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes for this LDIF add change record.
   *                     It must not be {@code null} or empty.
   * @param  controls    The set of controls for this LDIF add change record.
   *                     It may be {@code null} or empty if there are no
   *                     controls.
   */
  public LDIFAddChangeRecord(@NotNull final String dn,
                             @NotNull final Attribute[] attributes,
                             @Nullable final List<Control> controls)
  {
    super(dn, controls);

    Validator.ensureNotNull(attributes);
    Validator.ensureTrue(attributes.length > 0,
         "LDIFAddChangeRecord.attributes must not be empty.");

    this.attributes = attributes;
  }



  /**
   * Creates a new LDIF add change record with the provided DN and attributes.
   *
   * @param  dn          The DN for this LDIF add change record.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes for this LDIF add change record.
   *                     It must not be {@code null} or empty.
   */
  public LDIFAddChangeRecord(@NotNull final String dn,
                             @NotNull final List<Attribute> attributes)
  {
    this(dn, attributes, null);
  }



  /**
   * Creates a new LDIF add change record with the provided DN and attributes.
   *
   * @param  dn          The DN for this LDIF add change record.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes for this LDIF add change record.
   *                     It must not be {@code null} or empty.
   * @param  controls    The set of controls for this LDIF add change record.
   *                     It may be {@code null} or empty if there are no
   *                     controls.
   */
  public LDIFAddChangeRecord(@NotNull final String dn,
                             @NotNull final List<Attribute> attributes,
                             @Nullable final List<Control> controls)
  {
    super(dn, controls);

    Validator.ensureNotNull(attributes);
    Validator.ensureFalse(attributes.isEmpty(),
         "LDIFAddChangeRecord.attributes must not be empty.");

    this.attributes = new Attribute[attributes.size()];
    attributes.toArray(this.attributes);
  }



  /**
   * Creates a new LDIF add change record from the provided entry.
   *
   * @param  entry  The entry to use to create this LDIF add change record.  It
   *                must not be {@code null}.
   */
  public LDIFAddChangeRecord(@NotNull final Entry entry)
  {
    this(entry, Collections.<Control>emptyList());
  }



  /**
   * Creates a new LDIF add change record from the provided entry.
   *
   * @param  entry     The entry to use to create this LDIF add change record.
   *                   It must not be {@code null}.
   * @param  controls  The set of controls for this LDIF add change record.  It
   *                   may be {@code null} or empty if there are no controls.
   */
  public LDIFAddChangeRecord(@NotNull final Entry entry,
                             @Nullable final List<Control> controls)
  {
    super(entry.getDN(), controls);

    final Collection<Attribute> attrs = entry.getAttributes();
    attributes = new Attribute[attrs.size()];

    final Iterator<Attribute> iterator = attrs.iterator();
    for (int i=0; i < attributes.length; i++)
    {
      attributes[i] = iterator.next();
    }
  }



  /**
   * Creates a new LDIF add change record from the provided add request.
   *
   * @param  addRequest  The add request to use to create this LDIF add change
   *                     record.  It must not be {@code null}.
   */
  public LDIFAddChangeRecord(@NotNull final AddRequest addRequest)
  {
    super(addRequest.getDN(), addRequest.getControlList());

    final List<Attribute> attrs = addRequest.getAttributes();
    attributes = new Attribute[attrs.size()];

    final Iterator<Attribute> iterator = attrs.iterator();
    for (int i=0; i < attributes.length; i++)
    {
      attributes[i] = iterator.next();
    }
  }



  /**
   * Retrieves the set of attributes for this add change record.
   *
   * @return  The set of attributes for this add change record.
   */
  @NotNull()
  public Attribute[] getAttributes()
  {
    return attributes;
  }



  /**
   * Retrieves the entry that would be created by this add change record.
   *
   * @return  The entry that would be created by this add change record.
   */
  @NotNull()
  public Entry getEntryToAdd()
  {
    return new Entry(getDN(), attributes);
  }



  /**
   * Creates an add request from this LDIF add change record.    Any controls
   * included in this change record will be included in the request.
   *
   * @return  The add request created from this LDIF add change record.
   */
  @NotNull()
  public AddRequest toAddRequest()
  {
    return toAddRequest(true);
  }



  /**
   * Creates an add request from this LDIF add change record, optionally
   * including any change record controls in the request.
   *
   * @param  includeControls  Indicates whether to include any controls in the
   *                          request.
   *
   * @return  The add request created from this LDIF add change record.
   */
  @NotNull()
  public AddRequest toAddRequest(final boolean includeControls)
  {
    final AddRequest addRequest = new AddRequest(getDN(), attributes);
    if (includeControls)
    {
      addRequest.setControls(getControls());
    }

    return addRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ChangeType getChangeType()
  {
    return ChangeType.ADD;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDIFAddChangeRecord duplicate(@Nullable final Control... controls)
  {
    return new LDIFAddChangeRecord(getDN(), attributes,
         StaticUtils.toList(controls));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult processChange(@NotNull final LDAPInterface connection,
                                  final boolean includeControls)
         throws LDAPException
  {
    return connection.add(toAddRequest(includeControls));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String[] toLDIF(final int wrapColumn)
  {
    List<String> ldifLines = new ArrayList<>(2*attributes.length);
    encodeNameAndValue("dn", new ASN1OctetString(getDN()), ldifLines);

    for (final Control c : getControls())
    {
      encodeNameAndValue("control", encodeControlString(c), ldifLines);
    }

    ldifLines.add("changetype: add");

    for (final Attribute a : attributes)
    {
      final String name = a.getName();
      for (final ASN1OctetString value : a.getRawValues())
      {
        encodeNameAndValue(name, value, ldifLines);
      }
    }

    if (wrapColumn > 2)
    {
      ldifLines = LDIFWriter.wrapLines(wrapColumn, ldifLines);
    }

    final String[] ldifArray = new String[ldifLines.size()];
    ldifLines.toArray(ldifArray);
    return ldifArray;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toLDIF(@NotNull final ByteStringBuffer buffer,
                     final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
         wrapColumn);
    buffer.append(StaticUtils.EOL_BYTES);

    for (final Control c : getControls())
    {
      LDIFWriter.encodeNameAndValue("control", encodeControlString(c), buffer,
           wrapColumn);
      buffer.append(StaticUtils.EOL_BYTES);
    }

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("add"),
                                  buffer, wrapColumn);
    buffer.append(StaticUtils.EOL_BYTES);

    for (final Attribute a : attributes)
    {
      final String name = a.getName();
      for (final ASN1OctetString value : a.getRawValues())
      {
        LDIFWriter.encodeNameAndValue(name, value, buffer, wrapColumn);
        buffer.append(StaticUtils.EOL_BYTES);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toLDIFString(@NotNull final StringBuilder buffer,
                           final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
         wrapColumn);
    buffer.append(StaticUtils.EOL);

    for (final Control c : getControls())
    {
      LDIFWriter.encodeNameAndValue("control", encodeControlString(c), buffer,
           wrapColumn);
      buffer.append(StaticUtils.EOL);
    }

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("add"),
                                  buffer, wrapColumn);
    buffer.append(StaticUtils.EOL);

    for (final Attribute a : attributes)
    {
      final String name = a.getName();
      for (final ASN1OctetString value : a.getRawValues())
      {
        LDIFWriter.encodeNameAndValue(name, value, buffer, wrapColumn);
        buffer.append(StaticUtils.EOL);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int hashCode()
  {
    try
    {
      int hashCode = getParsedDN().hashCode();
      for (final Attribute a : attributes)
      {
        hashCode += a.hashCode();
      }

      return hashCode;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return new Entry(getDN(), attributes).hashCode();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof LDIFAddChangeRecord))
    {
      return false;
    }

    final LDIFAddChangeRecord r = (LDIFAddChangeRecord) o;

    final HashSet<Control> c1 = new HashSet<>(getControls());
    final HashSet<Control> c2 = new HashSet<>(r.getControls());
    if (! c1.equals(c2))
    {
      return false;
    }

    final Entry e1 = new Entry(getDN(), attributes);
    final Entry e2 = new Entry(r.getDN(), r.attributes);
    return e1.equals(e2);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDIFAddChangeRecord(dn='");
    buffer.append(getDN());
    buffer.append("', attrs={");

    for (int i=0; i < attributes.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      attributes[i].toString(buffer);
    }
    buffer.append('}');

    final List<Control> controls = getControls();
    if (! controls.isEmpty())
    {
      buffer.append(", controls={");

      final Iterator<Control> iterator = controls.iterator();
      while (iterator.hasNext())
      {
        iterator.next().toString(buffer);
        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
    }

    buffer.append(')');
  }
}
