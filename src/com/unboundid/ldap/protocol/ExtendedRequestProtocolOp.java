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
package com.unboundid.ldap.protocol;



import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.protocol.ProtocolMessages.*;



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
  @Nullable private final ASN1OctetString value;

  // The OID for this extended request.
  @NotNull private final String oid;



  /**
   * Creates a new extended request protocol op with the provided information.
   *
   * @param  oid    The OID for this extended request.
   * @param  value  The value for this extended request, or {@code null} if
   *                there should not be a value.
   */
  public ExtendedRequestProtocolOp(@NotNull final String oid,
                                   @Nullable final ASN1OctetString value)
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
   * Creates a new extended request protocol op from the provided extended
   * request object.
   *
   * @param  request  The extended request object to use to create this protocol
   *                  op.
   */
  public ExtendedRequestProtocolOp(@NotNull final ExtendedRequest request)
  {
    oid   = request.getOID();
    value = request.getValue();
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
  ExtendedRequestProtocolOp(@NotNull final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence opSequence = reader.beginSequence();
      oid = reader.readString();
      Validator.ensureNotNull(oid);

      if (opSequence.hasMoreElements())
      {
        value = new ASN1OctetString(TYPE_VALUE, reader.readBytes());
      }
      else
      {
        value = null;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXTENDED_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the OID for this extended request.
   *
   * @return  The OID for this extended request.
   */
  @NotNull()
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
  @Nullable()
  public ASN1OctetString getValue()
  {
    return value;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    if (value ==  null)
    {
      return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
           new ASN1OctetString(TYPE_OID, oid));
    }
    else
    {
      return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST,
           new ASN1OctetString(TYPE_OID, oid),
           value);
    }
  }



  /**
   * Decodes the provided ASN.1 element as an extended request protocol op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded extended request protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         an extended request protocol op.
   */
  @NotNull()
  public static ExtendedRequestProtocolOp decodeProtocolOp(
                     @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String oid =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      final ASN1OctetString value;
      if (elements.length == 1)
      {
        value = null;
      }
      else
      {
        value = ASN1OctetString.decodeAsOctetString(elements[1]);
      }

      return new ExtendedRequestProtocolOp(oid, value);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXTENDED_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(@NotNull final ASN1Buffer buffer)
  {
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);
    buffer.addOctetString(TYPE_OID, oid);

    if (value != null)
    {
      buffer.addOctetString(TYPE_VALUE, value.getValue());
    }
    opSequence.end();
  }



  /**
   * Creates an extended request from this protocol op.
   *
   * @param  controls  The set of controls to include in the extended request.
   *                   It may be empty or {@code null} if no controls should be
   *                   included.
   *
   * @return  The extended request that was created.
   */
  @NotNull()
  public ExtendedRequest toExtendedRequest(@Nullable final Control... controls)
  {
    return new ExtendedRequest(oid, value, controls);
  }



  /**
   * Retrieves a string representation of this protocol op.
   *
   * @return  A string representation of this protocol op.
   */
  @Override()
  @NotNull()
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
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ExtendedRequestProtocolOp(oid='");
    buffer.append(oid);
    buffer.append("')");
  }
}
