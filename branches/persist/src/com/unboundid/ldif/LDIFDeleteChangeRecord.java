/*
 * Copyright 2007-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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



import java.util.Arrays;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ChangeType;
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
  private static final long serialVersionUID = 486284031156138191L;



  /**
   * Creates a new LDIF delete change record with the provided DN.
   *
   * @param  dn  The DN of the entry to delete.  It must not be {@code null}.
   */
  public LDIFDeleteChangeRecord(final String dn)
  {
    super(dn);
  }



  /**
   * Creates a new LDIF delete change record from the provided delete request.
   *
   * @param  deleteRequest  The delete request to use to create this LDIF delete
   *                        change record.  It must not be {@code null}.
   */
  public LDIFDeleteChangeRecord(final DeleteRequest deleteRequest)
  {
    super(deleteRequest.getDN());
  }



  /**
   * Creates a delete request from this LDIF delete change record.
   *
   * @return  The delete request created from this LDIF delete change record.
   */
  public DeleteRequest toDeleteRequest()
  {
    return new DeleteRequest(getDN());
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
  public LDAPResult processChange(final LDAPInterface connection)
         throws LDAPException
  {
    return connection.delete(toDeleteRequest());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String[] toLDIF(final int wrapColumn)
  {
    if (wrapColumn > 0)
    {
      List<String> ldifLines = Arrays.asList(
           LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN())),
           "changetype: delete");

      ldifLines = LDIFWriter.wrapLines(wrapColumn, ldifLines);

      final String[] lineArray = new String[ldifLines.size()];
      return ldifLines.toArray(lineArray);
    }
    else
    {
      return new String[]
      {
        LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN())),
        "changetype: delete"
      };
    }
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
    catch (Exception e)
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

    try
    {
      return getParsedDN().equals(r.getParsedDN());
    }
    catch (Exception e)
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
    buffer.append("')");
  }
}
