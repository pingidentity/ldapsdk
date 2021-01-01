/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an intermediate response that can
 * provide the client with output from the collect-support-data tool in
 * response to a {@link CollectSupportDataExtendedRequest}.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The collect support data output intermediate response has an OID of
 * 1.3.6.1.4.1.30221.2.6.65 and a value with the following encoding:
 * <BR>
 * <PRE>
 *   CollectSupportDataOutputIntermediateResponse ::= SEQUENCE {
 *      outputStream      [0] ENUMERATED {
 *           standardOutput     (0),
 *           standardError      (1),
 *           ... },
 *      outputMessage     [1] OCTET STRING,
 *      ... }
 * </PRE>
 *
 * @see  CollectSupportDataExtendedRequest
 * @see  CollectSupportDataExtendedResult
 * @see  CollectSupportDataArchiveFragmentIntermediateResponse
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CollectSupportDataOutputIntermediateResponse
       extends IntermediateResponse
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.65) for the collect support data output
   * intermediate response.
   */
  @NotNull public static final String
       COLLECT_SUPPORT_DATA_OUTPUT_INTERMEDIATE_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.6.65";



  /**
   * The BER type for the value element that specifies the output stream.
   */
  private static final byte TYPE_OUTPUT_STREAM = (byte) 0x80;



  /**
   * The BER type for the value element that specifies the output message.
   */
  private static final byte TYPE_OUTPUT_MESSAGE = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2844901273280769861L;



  // The output stream to which the message was written.
  @NotNull private final CollectSupportDataOutputStream outputStream;

  // The output message that was written.
  @NotNull private final String outputMessage;



  /**
   * Creates a new collect support data output intermediate response with the
   * provided information.
   *
   * @param  outputStream   The output stream to which the message was written.
   *                        It must not be {@code null}.
   * @param  outputMessage  The output message that was written by the tool.  It
   *                        must not be {@code null}.
   * @param  controls       The set of controls to include in this intermediate
   *                        response.  It may be {@code null} or empty if no
   *                        controls are needed.
   */
  public CollectSupportDataOutputIntermediateResponse(
              @NotNull final CollectSupportDataOutputStream outputStream,
              @NotNull final String outputMessage,
              @Nullable final Control... controls)
  {
    super(COLLECT_SUPPORT_DATA_OUTPUT_INTERMEDIATE_RESPONSE_OID,
         encodeValue(outputStream, outputMessage), controls);

    this.outputStream = outputStream;
    this.outputMessage = outputMessage;
  }



  /**
   * Constructs an ASN.1 octet string suitable for use as the value of this
   * collect support data output intermediate response.
   *
   * @param  outputStream   The output stream to which the message was written.
   *                        It must not be {@code null}.
   * @param  outputMessage  The output message that was written by the tool.  It
   *                        must not be {@code null}.
   *
   * @return  The ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @NotNull final CollectSupportDataOutputStream outputStream,
               @NotNull final String outputMessage)
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated(TYPE_OUTPUT_STREAM, outputStream.getIntValue()),
         new ASN1OctetString(TYPE_OUTPUT_MESSAGE, outputMessage));

    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Creates a new collect support data output intermediate response that is
   * decoded from the provided generic intermediate response.
   *
   * @param  intermediateResponse  The generic intermediate response to be
   *                               decoded as a collect support data output
   *                               intermediate response.  It must not be
   *                               {@code null}.
   *
   * @throws  LDAPException  If the provided intermediate response object cannot
   *                         be decoded as a collect support data output
   *                         intermediate response.
   */
  public CollectSupportDataOutputIntermediateResponse(
              @NotNull final IntermediateResponse intermediateResponse)
         throws LDAPException
  {
    super(intermediateResponse);

    final ASN1OctetString value = intermediateResponse.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CSD_OUTPUT_IR_DECODE_NO_VALUE.get());
    }

    try
    {
      final ASN1Sequence valueSequence =
           ASN1Sequence.decodeAsSequence(value.getValue());
      final ASN1Element[] elements = valueSequence.elements();

      final int outputStreamIntValue =
           ASN1Enumerated.decodeAsEnumerated(elements[0]).intValue();
      outputStream = CollectSupportDataOutputStream.forIntValue(
           outputStreamIntValue);
      if (outputStream == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CSD_OUTPUT_IR_DECODE_UNRECOGNIZED_OUTPUT_STREAM.get(
                  outputStreamIntValue));
      }

      outputMessage =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CSD_OUTPUT_IR_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the output stream to which the output message was written.
   *
   * @return  The output stream to which the output was written.
   */
  @NotNull()
  public CollectSupportDataOutputStream getOutputStream()
  {
    return outputStream;
  }



  /**
   * Retrieves the output message that was written.
   *
   * @return  The output message that was written.
   */
  @NotNull()
  public String getOutputMessage()
  {
    return outputMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getIntermediateResponseName()
  {
    return INFO_COLLECT_SUPPORT_DATA_OUTPUT_IR_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String valueToString()
  {
    final StringBuilder buffer = new StringBuilder();

    buffer.append("outputStream='");
    buffer.append(outputStream.getName());
    buffer.append("' outputMessage='");
    buffer.append(outputMessage);
    buffer.append('\'');

    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("CollectSupportDataOutputIntermediateResponse(oid='");
    buffer.append(getOID());
    buffer.append("', outputStream='");
    buffer.append(outputStream.getName());
    buffer.append("', outputMessage='");
    buffer.append(outputMessage);
    buffer.append('\'');

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
