/*
 * Copyright 2021-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2024 Ping Identity Corporation
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
 * Copyright (C) 2021-2024 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class defines the superclass for extended results that may be returned
 * in response to the replace certificate extended requests, including
 * {@link ReplaceListenerCertificateExtendedRequest},
 * {@link ReplaceInterServerCertificateExtendedRequest},
 * {@link PurgeRetiredListenerCertificatesExtendedRequest}, and
 * {@link PurgeRetiredInterServerCertificatesExtendedRequest}.
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
 * The extended result may have an OID that matches that of the associated
 * extended result, and it may have a value with the following encoding:
 * <PRE>
 *   ReplaceCertificateResponseValue ::= SEQUENCE {
 *     toolOutput     [16] OCTET STRING OPTIONAL,
 *    ... }
 * </PRE>
 * <BR><BR>
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class ReplaceCertificateExtendedResult
       extends ExtendedResult
{
  /**
   * The BER type for the response value element that holds the output of the
   * {@code replace-certificate} tool.
   */
  private static final byte TYPE_TOOL_OUTPUT = (byte) 0x91;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4865907062468450991L;



  // The output obtained when running the replace-certificate tool.
  @Nullable private final String toolOutput;



  /**
   * Creates a new replace certificate extended result that is decoded from the
   * provided extended result.
   *
   * @param  extendedResult  The generic extended result to decode as a replace
   *                         certificate extended result.  It must not be
   *                         {@code null}.
   *
   * @throws  LDAPException  If the provided extended result cannot be decoded
   *                         as a replace certificate extended result.
   */
  protected ReplaceCertificateExtendedResult(
                 @NotNull final ExtendedResult extendedResult)
            throws LDAPException
  {
    super(extendedResult);

    String output = null;
    final ASN1OctetString value = extendedResult.getValue();
    if (value != null)
    {
      try
      {
        for (final ASN1Element element :
             ASN1Sequence.decodeAsSequence(value.getValue()).elements())
        {
          switch (element.getType())
          {
            case TYPE_TOOL_OUTPUT:
              output = element.decodeAsOctetString().stringValue();
              break;
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_REPLACE_CERT_RESULT_CANNOT_DECODE_VALUE.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    toolOutput = output;
  }



  /**
   * Creates a new replace certificate extended result with the provided
   * information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  oid                The OID to use for the extended result.  It may
   *                            be {@code null} if no OID should be used.
   * @param  toolOutput         The output (a combined representation of both
   *                            standard output and standard error) obtained
   *                            from running the {@code replace-certificate}
   *                            tool.  It may be {@code null} if request
   *                            processing failed before running the tool.
   * @param  responseControls   The set of controls to include in the extended
   *                            result.  It may be {@code null} or empty if no
   *                            response controls should be included.
   */
  protected ReplaceCertificateExtendedResult(final int messageID,
                 @NotNull final ResultCode resultCode,
                 @Nullable final String diagnosticMessage,
                 @Nullable final String matchedDN,
                 @Nullable final String[] referralURLs,
                 @Nullable final String oid,
                 @Nullable final String toolOutput,
                 @Nullable final Control... responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         oid, encodeValue(oid, toolOutput), responseControls);

    this.toolOutput = toolOutput;
  }



  /**
   * Encodes a value for this extended result, if appropriate.
   *
   * @param  oid         The OID to use for the extended result.  It may be
   *                     {@code null} if no OID should be used.
   * @param  toolOutput  The output obtained from running the
   *                     {@code replace-certificate} tool.  It may be
   *                     {@code null} if request processing failed before
   *                     running the tool.
   *
   * @return  The encoded value for this extended result, or {@code null} if
   *          no value should be included.
   */
  @Nullable()
  public static ASN1OctetString encodeValue(@Nullable final String oid,
                                            @Nullable final String toolOutput)
  {
    if ((oid == null) && (toolOutput == null))
    {
      return null;
    }

    final List<ASN1Element> valueElements = new ArrayList<>(1);
    if (toolOutput != null)
    {
      valueElements.add(new ASN1OctetString(TYPE_TOOL_OUTPUT, toolOutput));
    }

    final ASN1Sequence valueSequence = new ASN1Sequence(valueElements);
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Retrieves the output (a combined representation of both standard output and
   * standard error) obtained from running the {@code replace-certificate} tool,
   * if available.
   *
   * @return  The output obtained from running the {@code replace-certificate}
   *          tool, or {@code null} if no output is available (e.g., because
   *          an error occurred before the tool could be invoked).
   */
  @Nullable()
  public String getToolOutput()
  {
    return toolOutput;
  }



  /**
   * Appends a string representation of this replace certificate result to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.  It
   *                 must not be {@code null}.
   */
  @Override()
  public final void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ReplaceCertificateExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    final String diagnosticMessage = getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    final String matchedDN = getMatchedDN();
    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    final String[] referralURLs = getReferralURLs();
    if (referralURLs.length > 0)
    {
      buffer.append(", referralURLs={");
      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(referralURLs[i]);
        buffer.append('\'');
      }
      buffer.append('}');
    }

    final String oid = getOID();
    if (oid != null)
    {
      buffer.append(", oid='");
      buffer.append(oid);
      buffer.append('\'');
    }

    if (toolOutput != null)
    {
      buffer.append(", toolOutput='");
      escapeOutput(toolOutput, buffer);
      buffer.append('\'');
    }

    final Control[] responseControls = getResponseControls();
    if (responseControls.length > 0)
    {
      buffer.append(", responseControls={");
      for (int i=0; i < responseControls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(responseControls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }



  /**
   * Appends an escaped representation of the provided output to the given
   * buffer.
   *
   * @param  toolOutput  The output to be escaped.  It must not be {@code null}.
   * @param  buffer      The buffer to which the escaped representation should
   *                     be appended.  It must not be {@code null}.
   */
  private static void escapeOutput(@NotNull final String toolOutput,
                                   @NotNull final StringBuilder buffer)
  {
    for (final char c : toolOutput.toCharArray())
    {
      switch (c)
      {
        case '\\':
          buffer.append("\\\\");
          break;
        case '\n':
          buffer.append("\\n");
          break;
        case '\r':
          buffer.append("\\r");
          break;
        case '\'':
          buffer.append("\\'");
          break;
        case '"':
          buffer.append("\\\"");
          break;
        default:
          buffer.append(c);
          break;
      }
    }
  }
}
