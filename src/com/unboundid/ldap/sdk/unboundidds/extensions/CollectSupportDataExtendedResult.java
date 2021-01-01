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
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
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
 * This class provides an implementation of an extended result that provides
 * information about the result of processing a
 * {@link CollectSupportDataExtendedRequest}.  Once this message has been
 * received, all processing for the associated request will be complete, and
 * there should not be any further
 * {@link CollectSupportDataOutputIntermediateResponse} or
 * {@link CollectSupportDataArchiveFragmentIntermediateResponse} messages.
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
 * If the extended operation processing failed for some reason before the server
 * could invoke the collect-support-data tool, then this response may not
 * include an OID or value.  However, if the collect-support-data tool has been
 * invoked (regardless of its success or failure), then the extended result
 * should have an OID of1.3.6.1.4.1.30221.2.6.67 and a value with the following
 * encoding:
 * <BR>
 * <PRE>
 *   CollectSupportDataResponse ::= SEQUENCE {
 *      exitCode     [0] INTEGER,
 *      ... }
 * </PRE>
 *
 * @see  CollectSupportDataExtendedRequest
 * @see  CollectSupportDataArchiveFragmentIntermediateResponse
 * @see  CollectSupportDataOutputIntermediateResponse
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CollectSupportDataExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.67) for the collect support data extended
   * result.
   */
  @NotNull public static final String COLLECT_SUPPORT_DATA_RESULT_OID =
       "1.3.6.1.4.1.30221.2.6.67";



  /**
   * The BER type for the value element that holds the collect-support-data tool
   * exit code.
   */
  private static final byte TYPE_EXIT_CODE = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 9005943853349941187L;



  // The exit code returned by the collect-support-data tool.
  @Nullable private final Integer exitCode;



  /**
   * Creates a new collect support data extended result with the provided
   * information.
   *
   * @param  messageID          The LDAP message ID for this extended result.
   * @param  resultCode         The result code for this extended result.  It
   *                            must not be {@code null}.
   * @param  diagnosticMessage  The diagnostic message for this extended result.
   *                            It may be {@code null} if no diagnostic message
   *                            should be included.
   * @param  matchedDN          The matched DN for this extended result.  It may
   *                            be {@code null} if no matched DN should be
   *                            included.
   * @param  referralURLs       The set of referral URLs for this extended
   *                            result.  It may be {@code null} or empty if no
   *                            referral URLs should be included.
   * @param  exitCode           The exit code returned when the
   *                            collect-support-data tool completed.  This may
   *                            be {@code null} if extended operation processing
   *                            failed before the collect-support-data tool
   *                            could complete.
   * @param  controls           The set of controls to include in the extended
   *                            result.  It may be [@code null} or empty if no
   *                            controls should be included.
   */
  public CollectSupportDataExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final Integer exitCode,
              @Nullable final Control... controls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         (exitCode == null) ? null : COLLECT_SUPPORT_DATA_RESULT_OID,
         encodeValue(exitCode), controls);

    this.exitCode = exitCode;
  }



  /**
   * Constructs an ASN.1 octet string suitable for use as the value of this
   * extended result.
   *
   * @param  exitCode  The exit code returned when the collect-support-data tool
   *                   completed.  This may be {@code null} if extended
   *                   operation processing failed before the
   *                   collect-support-data tool could complete.
   *
   * @return  The ASN.1 octet string created for use as the value of this
   *          extended result, or {@code null} if the extended result should not
   *          have a value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(@Nullable final Integer exitCode)
  {
    if (exitCode == null)
    {
      return null;
    }

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer(TYPE_EXIT_CODE, exitCode));

    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Creates a new collect support data extended result that is decoded from
   * the provided generic extended result.
   *
   * @param  extendedResult  The generic extended result to be decoded as a
   *                         collect support data extended result.  It must not
   *                         be {@code null}.
   *
   * @throws  LDAPException  If the provided generic extended result cannot be
   *                         decoded as a collect support data extended result.
   */
  public CollectSupportDataExtendedResult(
              @NotNull final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      exitCode = null;
      return;
    }

    try
    {
      final ASN1Sequence valueSequence =
           ASN1Sequence.decodeAsSequence(value.getValue());
      final ASN1Element[] elements = valueSequence.elements();
      exitCode = ASN1Integer.decodeAsInteger(elements[0]).intValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CSD_RESULT_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the exit code returned when the collect-support-data tool
   * completed.
   *
   * @return  The exit code returned when the collect-support-data tool
   *          completed, or {@code null} if extended operation processing
   *          failed before the collect-support-data tool could complete.
   */
  @Nullable()
  public Integer getExitCode()
  {
    return exitCode;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_COLLECT_SUPPORT_DATA_RESULT_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("CollectSupportDataExtendedResult(resultCode=");
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

    if (exitCode != null)
    {
      buffer.append(", exitCode=");
      buffer.append(exitCode);
    }

    final Control[] responseControls = getResponseControls();
    if (responseControls.length > 0)
    {
      buffer.append(", controls={");
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
}
