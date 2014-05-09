/*
 * Copyright 2009-2012 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2012 UnboundID Corp.
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



/**
 * This class provides an implementation of an LDAP intermediate response
 * protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IntermediateResponseProtocolOp
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
  private static final long serialVersionUID = 118549806265654465L;



  // The value for this intermediate response.
  private final ASN1OctetString value;

  // The OID for this intermediate response.
  private final String oid;



  /**
   * Creates a new intermediate response protocol op with the provided
   * information.
   *
   * @param  oid    The OID for this intermediate response, or {@code null} if
   *                there should not be an OID.
   * @param  value  The value for this intermediate response, or {@code null} if
   *                there should not be a value.
   */
  public IntermediateResponseProtocolOp(final String oid,
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
   * Creates a new intermediate response protocol op read from the provided
   * ASN.1 stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the intermediate
   *                 response protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         intermediate response.
   */
  IntermediateResponseProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence opSequence = reader.beginSequence();

      String o = null;
      ASN1OctetString v = null;
      while (opSequence.hasMoreElements())
      {
        final byte type = (byte) reader.peek();
        if (type == TYPE_OID)
        {
          o = reader.readString();
        }
        else if (type == TYPE_VALUE)
        {
          v = new ASN1OctetString(type, reader.readBytes());
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_INTERMEDIATE_RESPONSE_INVALID_ELEMENT.get(toHex(type)));
        }
      }

      oid = o;
      value = v;
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
           ERR_INTERMEDIATE_RESPONSE_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the OID for this intermediate response, if any.
   *
   * @return  The OID for this intermediate response, or {@code null} if there
   *          is no response OID.
   */
  public String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the value for this intermediate response, if any.
   *
   * @return  The value for this intermediate response, or {@code null} if there
   *          is no response value.
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
    return LDAPMessage.PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE;
  }



  /**
   * {@inheritDoc}
   */
  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence = buffer.beginSequence(
         LDAPMessage.PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE);

    if (oid != null)
    {
      buffer.addOctetString(TYPE_OID, oid);
    }

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
    buffer.append("IntermediateResponseProtocolOp(");

    if (oid != null)
    {
      buffer.append("oid='");
      buffer.append(oid);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
