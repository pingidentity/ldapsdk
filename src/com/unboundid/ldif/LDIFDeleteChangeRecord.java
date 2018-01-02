/*
 * Copyright 2007-2018 Ping Identity Corporation
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
package com.unboundid.ldif;



import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class defines an LDIF delete change record, which can be used to
 * represent an LDAP delete request.  See the documentation for the
 * {@link LDIFChangeRecord} class for an example demonstrating the process for
 * interacting with LDIF change records.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDIFDeleteChangeRecord
       extends LDIFChangeRecord
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 9173178539060889790L;



  /**
   * Creates a new LDIF delete change record with the provided DN.
   *
   * @param  dn  The DN of the entry to delete.  It must not be {@code null}.
   */
  public LDIFDeleteChangeRecord(final String dn)
  {
    this(dn, null);
  }



  /**
   * Creates a new LDIF delete change record with the provided DN.
   *
   * @param  dn        The DN of the entry to delete.  It must not be
   *                   {@code null}.
   * @param  controls  The set of controls for this LDIF delete change record.
   *                   It may be {@code null} or empty if there are no controls.
   */
  public LDIFDeleteChangeRecord(final String dn, final List<Control> controls)
  {
    super(dn, controls);
  }



  /**
   * Creates a new LDIF delete change record from the provided delete request.
   *
   * @param  deleteRequest  The delete request to use to create this LDIF delete
   *                        change record.  It must not be {@code null}.
   */
  public LDIFDeleteChangeRecord(final DeleteRequest deleteRequest)
  {
    super(deleteRequest.getDN(), deleteRequest.getControlList());
  }



  /**
   * Creates a delete request from this LDIF delete change record. Any change
   * record controls will be included in the request
   *
   * @return The delete request created from this LDIF delete change record.
   */
  public DeleteRequest toDeleteRequest()
  {
    return toDeleteRequest(true);
  }



  /**
   * Creates a delete request from this LDIF delete change record, optionally
   * including any change record controls in the request.
   *
   * @param  includeControls  Indicates whether to include any controls in the
   *                          request.
   *
   * @return The delete request created from this LDIF delete change record.
   */
  public DeleteRequest toDeleteRequest(final boolean includeControls)
  {
    final DeleteRequest deleteRequest = new DeleteRequest(getDN());
    if (includeControls)
    {
      deleteRequest.setControls(getControls());
    }

    return deleteRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ChangeType getChangeType()
  {
    return ChangeType.DELETE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult processChange(final LDAPInterface connection,
                                  final boolean includeControls)
         throws LDAPException
  {
    return connection.delete(toDeleteRequest(includeControls));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String[] toLDIF(final int wrapColumn)
  {
    List<String> ldifLines = new ArrayList<String>(5);
    encodeNameAndValue("dn", new ASN1OctetString(getDN()), ldifLines);

    for (final Control c : getControls())
    {
      encodeNameAndValue("control", encodeControlString(c), ldifLines);
    }

    ldifLines.add("changetype: delete");

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

    for (final Control c : getControls())
    {
      LDIFWriter.encodeNameAndValue("control", encodeControlString(c), buffer,
           wrapColumn);
      buffer.append(EOL_BYTES);
    }

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("delete"),
                                  buffer, wrapColumn);
    buffer.append(EOL_BYTES);
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

    for (final Control c : getControls())
    {
      LDIFWriter.encodeNameAndValue("control", encodeControlString(c), buffer,
           wrapColumn);
      buffer.append(EOL);
    }

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("delete"),
                                  buffer, wrapColumn);
    buffer.append(EOL);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int hashCode()
  {
    try
    {
      return getParsedDN().hashCode();
    }
    catch (final Exception e)
    {
      debugException(e);
      return toLowerCase(getDN()).hashCode();
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

    if (! (o instanceof LDIFDeleteChangeRecord))
    {
      return false;
    }

    final LDIFDeleteChangeRecord r = (LDIFDeleteChangeRecord) o;

    final HashSet<Control> c1 = new HashSet<Control>(getControls());
    final HashSet<Control> c2 = new HashSet<Control>(r.getControls());
    if (! c1.equals(c2))
    {
      return false;
    }

    try
    {
      return getParsedDN().equals(r.getParsedDN());
    }
    catch (final Exception e)
    {
      debugException(e);
      return toLowerCase(getDN()).equals(toLowerCase(r.getDN()));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDIFDeleteChangeRecord(dn='");
    buffer.append(getDN());
    buffer.append('\'');

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
