/*
 * Copyright 2007-2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2011 UnboundID Corp.
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
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



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
  private static final long serialVersionUID = 5717427836786488295L;



  // The set of attributes for this add change record.
  private final Attribute[] attributes;



  /**
   * Creates a new LDIF add change record with the provided DN and attributes.
   *
   * @param  dn          The DN for this LDIF add change record.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes for this LDIF add change record.
   *                     It must not be {@code null} or empty.
   */
  public LDIFAddChangeRecord(final String dn, final Attribute... attributes)
  {
    super(dn);

    ensureNotNull(attributes);
    ensureTrue(attributes.length > 0,
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
  public LDIFAddChangeRecord(final String dn, final List<Attribute> attributes)
  {
    super(dn);

    ensureNotNull(attributes);
    ensureFalse(attributes.isEmpty(),
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
  public LDIFAddChangeRecord(final Entry entry)
  {
    super(entry.getDN());

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
  public LDIFAddChangeRecord(final AddRequest addRequest)
  {
    super(addRequest.getDN());

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
  public Attribute[] getAttributes()
  {
    return attributes;
  }



  /**
   * Creates an add request from this LDIF add change record.
   *
   * @return  The add request created from this LDIF add change record.
   */
  public AddRequest toAddRequest()
  {
    return new AddRequest(getDN(), attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ChangeType getChangeType()
  {
    return ChangeType.ADD;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult processChange(final LDAPInterface connection)
         throws LDAPException
  {
    return connection.add(toAddRequest());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String[] toLDIF(final int wrapColumn)
  {
    List<String> ldifLines = new ArrayList<String>(2*attributes.length);
    ldifLines.add(LDIFWriter.encodeNameAndValue("dn",
                                                new ASN1OctetString(getDN())));
    ldifLines.add("changetype: add");

    for (final Attribute a : attributes)
    {
      final String name = a.getName();
      for (final ASN1OctetString value : a.getRawValues())
      {
        ldifLines.add(LDIFWriter.encodeNameAndValue(name, value));
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
  public void toLDIF(final ByteStringBuffer buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
                                  wrapColumn);
    buffer.append(EOL_BYTES);
    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("add"),
                                  buffer, wrapColumn);
    buffer.append(EOL_BYTES);

    for (final Attribute a : attributes)
    {
      final String name = a.getName();
      for (final ASN1OctetString value : a.getRawValues())
      {
        LDIFWriter.encodeNameAndValue(name, value, buffer, wrapColumn);
        buffer.append(EOL_BYTES);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toLDIFString(final StringBuilder buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
                                  wrapColumn);
    buffer.append(EOL);

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("add"),
                                  buffer, wrapColumn);
    buffer.append(EOL);

    for (final Attribute a : attributes)
    {
      final String name = a.getName();
      for (final ASN1OctetString value : a.getRawValues())
      {
        LDIFWriter.encodeNameAndValue(name, value, buffer, wrapColumn);
        buffer.append(EOL);
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
    catch (Exception e)
    {
      debugException(e);
      return new Entry(getDN(), attributes).hashCode();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean equals(final Object o)
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

    final Entry e1 = new Entry(getDN(), attributes);
    final Entry e2 = new Entry(r.getDN(), r.attributes);
    return e1.equals(e2);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
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

    buffer.append("})");
  }
}
