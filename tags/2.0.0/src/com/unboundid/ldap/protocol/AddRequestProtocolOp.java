/*
 * Copyright 2009-2010 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2010 UnboundID Corp.
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
package com.unboundid.ldap.protocol;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides an implementation of an LDAP add request protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AddRequestProtocolOp
       implements ProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1195296296055518601L;



  // The list of attributes for this add request.
  private final List<Attribute> attributes;

  // The entry DN for this add request.
  private final String dn;



  /**
   * Creates a new add request protocol op with the provided information.
   *
   * @param  dn          The entry DN for this add request.
   * @param  attributes  The list of attributes to include in this add request.
   */
  public AddRequestProtocolOp(final String dn, final List<Attribute> attributes)
  {
    this.dn         = dn;
    this.attributes = Collections.unmodifiableList(attributes);
  }



  /**
   * Creates a new add request protocol op read from the provided ASN.1 stream
   * reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the add request
   *                 protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         add request.
   */
  AddRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      dn = reader.readString();
      ensureNotNull(dn);

      final ArrayList<Attribute> attrs = new ArrayList<Attribute>(10);
      final ASN1StreamReaderSequence attrSequence = reader.beginSequence();
      while (attrSequence.hasMoreElements())
      {
        attrs.add(Attribute.readFrom(reader));
      }

      attributes = Collections.unmodifiableList(attrs);
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw le;
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ADD_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves the target entry DN for this add request.
   *
   * @return  The target entry DN for this add request.
   */
  public String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the list of attributes for this add request.
   *
   * @return  The list of attributes for this add request.
   */
  public List<Attribute> getAttributes()
  {
    return attributes;
  }



  /**
   * {@inheritDoc}
   */
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST);
    buffer.addOctetString(dn);

    final ASN1BufferSequence attrSequence = buffer.beginSequence();
    for (final Attribute a : attributes)
    {
      a.writeTo(buffer);
    }
    attrSequence.end();
    opSequence.end();
  }



  /**
   * Retrieves a string representation of this protocol op.
   *
   * @return  A string representation of this protocol op.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("AddRequestProtocolOp(dn='");
    buffer.append(dn);
    buffer.append("', attrs={");

    final Iterator<Attribute> iterator = attributes.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append("})");
  }
}
