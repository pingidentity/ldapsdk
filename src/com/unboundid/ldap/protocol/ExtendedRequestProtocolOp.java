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



import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
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
 * This class provides an implementation of an LDAP extended request protocol
 * op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExtendedRequestProtocolOp
       implements ProtocolOp
{
  /**
   * The BER type for the OID element.
   */
  public static final byte TYPE_OID = (byte) 0x80;



  /**
   * The BER type for the value element.
   */
  public static final byte TYPE_VALUE = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5343424210200494377L;



  // The value for this extended request.
  private final ASN1OctetString value;

  // The OID for this extended request.
  private final String oid;



  /**
   * Creates a new extended request protocol op with the provided information.
   *
   * @param  oid    The OID for this extended request.
   * @param  value  The value for this extended request, or {@code null} if
   *                there should not be a value.
   */
  public ExtendedRequestProtocolOp(final String oid,
                                   final ASN1OctetString value)
  {
    this.oid = oid;

    if (value == null)
    {
      this.value = null;
    }
    else
    {
      this.value = new ASN1OctetString(TYPE_VALUE, value.getValue());
    }
  }



  /**
   * Creates a new extended request protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the extended
   *                 request protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         extended request.
   */
  ExtendedRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence opSequence = reader.beginSequence();
      oid = reader.readString();
      ensureNotNull(oid);

      if (opSequence.hasMoreElements())
      {
        value = new ASN1OctetString(TYPE_VALUE, reader.readBytes());
      }
      else
      {
        value = null;
      }
    }
    catch (Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXTENDED_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves the OID for this extended request.
   *
   * @return  The OID for this extended request.
   */
  public String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the value for this extended request, if any.
   *
   * @return  The value for this extended request, or {@code null} if there is
   *          no value.
   */
  public ASN1OctetString getValue()
  {
    return value;
  }



  /**
   * {@inheritDoc}
   */
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);
    buffer.addOctetString(TYPE_OID, oid);

    if (value != null)
    {
      buffer.addElement(value);
    }
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
    buffer.append("ExtendedRequestProtocolOp(oid='");
    buffer.append(oid);
    buffer.append("')");
  }
}
