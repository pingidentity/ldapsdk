/*
 * Copyright 2009-2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2011 UnboundID Corp.
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
 * This class provides an implementation of an LDAP search result entry protocol
 * op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResultEntryProtocolOp
       implements ProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6501366526364541767L;



  // The list of attributes for this search result entry.
  private final List<Attribute> attributes;

  // The entry DN for this search result entry.
  private final String dn;



  /**
   * Creates a new search result entry protocol op with the provided
   * information.
   *
   * @param  dn          The entry DN for this search result entry.
   * @param  attributes  The list of attributes to include in this search result
   *                     entry.
   */
  public SearchResultEntryProtocolOp(final String dn,
                                     final List<Attribute> attributes)
  {
    this.dn         = dn;
    this.attributes = Collections.unmodifiableList(attributes);
  }



  /**
   * Creates a new search result entry protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the search
   *                 result entry protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         search result entry.
   */
  SearchResultEntryProtocolOp(final ASN1StreamReader reader)
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
           ERR_SEARCH_ENTRY_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves the DN for this search result entry.
   *
   * @return  The DN for this search result entry.
   */
  public String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the list of attributes for this search result entry.
   *
   * @return  The list of attributes for this search result entry.
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
    return LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY;
  }



  /**
   * {@inheritDoc}
   */
  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY);
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
    buffer.append("SearchResultEntryProtocolOp(dn='");
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
