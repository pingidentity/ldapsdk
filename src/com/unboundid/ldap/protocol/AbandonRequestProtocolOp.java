/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1StreamReader;
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
 * This class provides an implementation of an LDAP abandon request protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AbandonRequestProtocolOp
       implements ProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7824390696388231825L;



  // The message ID of the operation to abandon.
  private final int idToAbandon;



  /**
   * Creates a new abandon request protocol op with the provided information.
   *
   * @param  idToAbandon  The message ID of the operation to abandon.
   */
  public AbandonRequestProtocolOp(final int idToAbandon)
  {
    this.idToAbandon = idToAbandon;
  }



  /**
   * Creates a new abandon request protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the abandon
   *                 request protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         abandon request.
   */
  AbandonRequestProtocolOp(final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      idToAbandon = reader.readInteger();
    }
    catch (final Exception e)
    {
      debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ABANDON_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * Retrieves the message ID of the operation to abandon.
   *
   * @return  The message ID of the operation to abandon.
   */
  public int getIDToAbandon()
  {
    return idToAbandon;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1Element encodeProtocolOp()
  {
    return new ASN1Integer(LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
         idToAbandon);
  }



  /**
   * Decodes the provided ASN.1 element as an abandon request protocol op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded abandon request protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         an abandon request protocol op.
   */
  public static AbandonRequestProtocolOp decodeProtocolOp(
                                              final ASN1Element element)
         throws LDAPException
  {
    try
    {
      return new AbandonRequestProtocolOp(
           ASN1Integer.decodeAsInteger(element).intValue());
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ABANDON_REQUEST_CANNOT_DECODE.get(getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(final ASN1Buffer buffer)
  {
    buffer.addInteger(LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST,
                      idToAbandon);
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
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("AbandonRequestProtocolOp(idToAbandon=");
    buffer.append(idToAbandon);
    buffer.append(')');
  }
}
