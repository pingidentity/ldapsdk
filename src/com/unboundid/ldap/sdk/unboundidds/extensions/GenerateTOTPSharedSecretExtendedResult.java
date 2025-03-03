/*
 * Copyright 2016-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2025 Ping Identity Corporation
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
 * Copyright (C) 2016-2025 Ping Identity Corporation
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
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended result that may be used
 * to provide the client with a TOTP shared secret generated by the server in
 * response to a {@link GenerateTOTPSharedSecretExtendedRequest}.
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
 * If the extended request was processed successfully, then this result will
 * have an OID of 1.3.6.1.4.1.30221.2.6.57 and a value with the following
 * encoding:
 * <BR><BR>
 * <PRE>
 *   GenerateTOTPSharedSecretResult ::= SEQUENCE {
 *        totpSharedSecret     [0] OCTET STRING }
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GenerateTOTPSharedSecretExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.57) for the generate TOTP shared secret
   * extended result.
   */
  @NotNull public static final String GENERATE_TOTP_SHARED_SECRET_RESULT_OID =
       "1.3.6.1.4.1.30221.2.6.57";



  /**
   * The BER type for the TOTP shared secret element of the result value
   * sequence.
   */
  private static final byte TYPE_TOTP_SHARED_SECRET = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8505040895542971346L;



  // The base32-encoded representation TOTP shared secret generated by the
  // server.
  @Nullable private final String totpSharedSecret;



  /**
   * Generates a new generate TOTP shared secret extended result for the case in
   * which the server was able to generate the requested TOTP shared secret.
   *
   * @param  messageID         The message ID for the LDAP message that is
   *                           associated with this LDAP result.
   * @param  totpSharedSecret  The base32-encoded representation of the TOTP
   *                            shared secret generated by the server.  It must
   *                           not be {@code null}.
   * @param  responseControls  The set of controls from the response, if
   *                           available.
   */
  public GenerateTOTPSharedSecretExtendedResult(final int messageID,
              @NotNull final String totpSharedSecret,
              @Nullable final Control... responseControls)
  {
    this(messageID, ResultCode.SUCCESS, null, null, null, totpSharedSecret,
         responseControls);
  }



  /**
   * Creates a new generate TOTP shared secret extended result with the provided
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
   * @param  totpSharedSecret   The base32-encoded representation of the TOTP
   *                            shared secret generated by the server, if
   *                            available.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public GenerateTOTPSharedSecretExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final String totpSharedSecret,
              @Nullable final Control... responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         ((totpSharedSecret == null)
              ? null
              : GENERATE_TOTP_SHARED_SECRET_RESULT_OID),
         encodeValue(totpSharedSecret), responseControls);

    this.totpSharedSecret = totpSharedSecret;

    if (totpSharedSecret == null)
    {
      Validator.ensureTrue((resultCode != ResultCode.SUCCESS),
           "If the result code is SUCCESS, the TOTP shared secret must be " +
                "non-null");
    }
  }



  /**
   * Creates a new generate TOTP shared secret extended result from the provided
   * extended result.
   *
   * @param  extendedResult  The extended result to be decoded as a generate
   *                         TOTP shared secret extended result.  It must not be
   *                         {@code null}.
   *
   * @throws  LDAPException  If the provided extended result cannot be decoded
   *                         as a generate TOTP shared secret result.
   */
  public GenerateTOTPSharedSecretExtendedResult(
              @NotNull final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      totpSharedSecret = null;
    }
    else
    {
      try
      {
        final ASN1Element[] elements =
             ASN1Sequence.decodeAsSequence(value.getValue()).elements();
        totpSharedSecret =
             ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_GEN_TOTP_SECRET_RESULT_ERROR_DECODING_VALUE.get(
                  StaticUtils.getExceptionMessage(e)));
      }
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended result.
   *
   * @param  totpSharedSecret   The base32-encoded representation of the TOTP
   *                            shared secret generated by the server, if
   *                            available.
   *
   * @return  The ASN.1 octet string suitable for use as the value of this
   *          extended result, or {@code null} if there should be no value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
               @Nullable final String totpSharedSecret)
  {
    if (totpSharedSecret == null)
    {
      return null;
    }

    return new ASN1OctetString(new ASN1Sequence(new ASN1OctetString(
         TYPE_TOTP_SHARED_SECRET, totpSharedSecret)).encode());
  }



  /**
   * Retrieves the base32-encoded representation of the TOTP shared secret
   * generated by the server, if available.
   *
   * @return  The base32-encoded representation of the TOTP shared secret
   *          generated by the server, or {@code null} if none was provided.
   */
  @Nullable()
  public String getTOTPSharedSecret()
  {
    return totpSharedSecret;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_GEN_TOTP_SECRET_RESULT_NAME.get();
  }



  /**
   * Appends a string representation of this extended result to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which a string representation of this
   *                 extended result will be appended.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GenerateTOTPSharedSecretExtendedResult(resultCode=");
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
}
