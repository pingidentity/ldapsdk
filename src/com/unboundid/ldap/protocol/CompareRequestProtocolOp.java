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
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.Control;
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
 * This class provides an implementation of an LDAP compare request protocol op.
 */
@InternalUseOnly()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CompareRequestProtocolOp
       implements ProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -562642367801440060L;



  // The assertion value for this compare request.
  @NotNull private final ASN1OctetString assertionValue;

  // The attribute name for this compare request.
  @NotNull private final String attributeName;

  // The entry DN for this compare request.
  @NotNull private final String dn;



  /**
   * Creates a new compare request protocol op with the provided information.
   *
   * @param  dn              The DN for this compare request.
   * @param  attributeName   The attribute name for this compare request.
   * @param  assertionValue  The assertion value for this compare request.
   */
  public CompareRequestProtocolOp(@NotNull final String dn,
                                  @NotNull final String attributeName,
                                  @NotNull final ASN1OctetString assertionValue)
  {
    this.dn             = dn;
    this.attributeName  = attributeName;
    this.assertionValue = assertionValue;
  }



  /**
   * Creates a new compare request protocol op from the provided compare request
   * object.
   *
   * @param  request  The compare request object to use to create this protocol
   *                  op.
   */
  public CompareRequestProtocolOp(@NotNull final CompareRequest request)
  {
    dn             = request.getDN();
    attributeName  = request.getAttributeName();
    assertionValue = request.getRawAssertionValue();
  }



  /**
   * Creates a new compare request protocol op read from the provided ASN.1
   * stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the compare
   *                 request protocol op.
   *
   * @throws  LDAPException  If a problem occurs while reading or parsing the
   *                         compare request.
   */
  CompareRequestProtocolOp(@NotNull final ASN1StreamReader reader)
       throws LDAPException
  {
    try
    {
      reader.beginSequence();
      dn = reader.readString();

      reader.beginSequence();
      attributeName = reader.readString();
      assertionValue = new ASN1OctetString(reader.readBytes());
      Validator.ensureNotNull(dn, attributeName, assertionValue);
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
   * Retrieves the DN for this compare request.
   *
   * @return  The DN for this compare request.
   */
  @NotNull()
  public String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the attribute name for this compare request.
   *
   * @return  The attribute name for this compare request.
   */
  @NotNull()
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * Retrieves the assertion value for this compare request.
   *
   * @return  The assertion value for this compare request.
   */
  @NotNull()
  public ASN1OctetString getAssertionValue()
  {
    return assertionValue;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST,
         new ASN1OctetString(dn),
         new ASN1Sequence(
              new ASN1OctetString(attributeName),
              assertionValue));
  }



  /**
   * Decodes the provided ASN.1 element as a compare request protocol op.
   *
   * @param  element  The ASN.1 element to be decoded.
   *
   * @return  The decoded compare request protocol op.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a compare request protocol op.
   */
  @NotNull()
  public static CompareRequestProtocolOp decodeProtocolOp(
                     @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final String dn =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      final ASN1Element[] avaElements =
           ASN1Sequence.decodeAsSequence(elements[1]).elements();
      final String attributeName =
           ASN1OctetString.decodeAsOctetString(avaElements[0]).stringValue();
      final ASN1OctetString assertionValue =
           ASN1OctetString.decodeAsOctetString(avaElements[1]);

      return new CompareRequestProtocolOp(dn, attributeName, assertionValue);
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
    final ASN1BufferSequence opSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST);
    buffer.addOctetString(dn);

    final ASN1BufferSequence avaSequence = buffer.beginSequence();
    buffer.addOctetString(attributeName);
    buffer.addElement(assertionValue);
    avaSequence.end();
    opSequence.end();
  }



  /**
   * Creates a compare request from this protocol op.
   *
   * @param  controls  The set of controls to include in the compare request.
   *                   It may be empty or {@code null} if no controls should be
   *                   included.
   *
   * @return  The compare request that was created.
   */
  @NotNull()
  public CompareRequest toCompareRequest(@Nullable final Control... controls)
  {
    return new CompareRequest(dn, attributeName, assertionValue.getValue(),
         controls);
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
    buffer.append("CompareRequestProtocolOp(dn='");
    buffer.append(dn);
    buffer.append("', attributeName='");
    buffer.append(attributeName);
    buffer.append("', assertionValue='");
    buffer.append(assertionValue.stringValue());
    buffer.append("')");
  }
}
