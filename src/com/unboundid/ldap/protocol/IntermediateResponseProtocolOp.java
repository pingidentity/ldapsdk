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



import java.util.ArrayList;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.IntermediateResponse;
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

import static com.unboundid.ldap.protocol.ProtocolMessages.*;



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
  @Nullable private final ASN1OctetString value;

  // The OID for this intermediate response.
  @Nullable private final String oid;



  /**
   * Creates a new intermediate response protocol op with the provided
   * information.
   *
   * @param  oid    The OID for this intermediate response, or {@code null} if
   *                there should not be an OID.
   * @param  value  The value for this intermediate response, or {@code null} if
   *                there should not be a value.
   */
  public IntermediateResponseProtocolOp(@Nullable final String oid,
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
   * Creates a new intermediate response protocol op from the provided
   * intermediate response object.
   *
   * @param  response  The intermediate response object to use to create this
   *                   protocol op.
   */
  public IntermediateResponseProtocolOp(
              @NotNull final IntermediateResponse response)
  {
    oid = response.getOID();

    final ASN1OctetString responseValue = response.getValue();
    if (responseValue == null)
    {
      value = null;
    }
    else
    {
      value = new ASN1OctetString(TYPE_VALUE, responseValue.getValue());
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
  IntermediateResponseProtocolOp(@NotNull final ASN1StreamReader reader)
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
               ERR_INTERMEDIATE_RESPONSE_INVALID_ELEMENT.get(
                    StaticUtils.toHex(type)));
        }
      }

      oid = o;
      value = v;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_INTERMEDIATE_RESPONSE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the OID for this intermediate response, if any.
   *
   * @return  The OID for this intermediate response, or {@code null} if there
   *          is no response OID.
   */
  @Nullable()
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
    return LDAPMessage.PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(2);

    if (oid != null)
    {
      elements.add(new ASN1OctetString(TYPE_OID, oid));
    }

    if (value != null)
    {
      elements.add(value);
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE,
         elements);
  }



  /**
   * Decodes the provided ASN.1 element as a intermediate response protocol op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded intermediate response protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a intermediate response protocol op.
   */
  @NotNull()
  public static IntermediateResponseProtocolOp decodeProtocolOp(
                     @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      String oid = null;
      ASN1OctetString value = null;
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(element).elements())
      {
        switch (e.getType())
        {
          case TYPE_OID:
            oid = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_VALUE:
            value = ASN1OctetString.decodeAsOctetString(e);
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_INTERMEDIATE_RESPONSE_INVALID_ELEMENT.get(
                      StaticUtils.toHex(e.getType())));
        }
      }

      return new IntermediateResponseProtocolOp(oid, value);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_COMPARE_REQUEST_CANNOT_DECODE.get(
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
   * Creates a intermediate response from this protocol op.
   *
   * @param  controls  The set of controls to include in the intermediate
   *                   response.  It may be empty or {@code null} if no controls
   *                   should be included.
   *
   * @return  The intermediate response that was created.
   */
  @NotNull()
  public IntermediateResponse toIntermediateResponse(
                                   @Nullable final Control... controls)
  {
    return new IntermediateResponse(-1, oid, value, controls);
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
