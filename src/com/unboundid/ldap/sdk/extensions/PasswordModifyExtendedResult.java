/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.extensions;


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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.extensions.ExtOpMessages.*;



/**
 * This class implements a data structure for storing the information from an
 * extended result for the password modify extended request as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc3062.txt">RFC 3062</A>.  It is identical
 * to the standard {@link ExtendedResult} object except that it is also able to
 * extract the generated password if one was included.  See the documentation
 * for the {@link PasswordModifyExtendedRequest} class for an example of this.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordModifyExtendedResult
       extends ExtendedResult
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -160274020063799410L;



  // The generated password from the response, if applicable.
  @Nullable private final ASN1OctetString generatedPassword;



  /**
   * Creates a new password modify extended result from the provided extended
   * result.
   *
   * @param  extendedResult  The extended result to be decoded as a password
   *                         modify extended result.  It must not be
   *                         {@code null}.
   *
   * @throws  LDAPException  If the provided extended result cannot be decoded
   *                         as a password modify extended result.
   */
  public PasswordModifyExtendedResult(
              @NotNull final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      generatedPassword = null;
      return;
    }

    final ASN1Element[] elements;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      elements = ASN1Sequence.decodeAsSequence(valueElement).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_MODIFY_RESPONSE_VALUE_NOT_SEQUENCE.get(e),
                              e);
    }

    if (elements.length == 0)
    {
      generatedPassword = null;
      return;
    }
    else if (elements.length != 1)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_MODIFY_RESPONSE_MULTIPLE_ELEMENTS.get());
    }

    generatedPassword = ASN1OctetString.decodeAsOctetString(elements[0]);
  }



  /**
   * Creates a new password modify extended result with the provided
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
   * @param  generatedPassword  The generated password for this response, if
   *                            available.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public PasswordModifyExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final ASN1OctetString generatedPassword,
              @Nullable final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          null, encodeValue(generatedPassword), responseControls);

    this.generatedPassword = generatedPassword;
  }



  /**
   * Encodes the value for this extended result using the provided information.
   *
   * @param  generatedPassword  The generated password for this response, if
   *                            available.
   *
   * @return  An ASN.1 octet string containing the encoded value, or
   *          {@code null} if there should not be an encoded value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
                      @Nullable final ASN1OctetString generatedPassword)
  {
    if (generatedPassword == null)
    {
      return null;
    }

    final ASN1Element[] elements =
    {
      new ASN1OctetString((byte) 0x80, generatedPassword.getValue())
    };

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the string representation of the generated password contained in
   * this extended result, if available.
   *
   * @return  The string representation of the generated password contained in
   *          this extended result, or {@code null} if no generated password was
   *          included in the extended result.
   */
  @Nullable()
  public String getGeneratedPassword()
  {
    if (generatedPassword == null)
    {
      return null;
    }
    else
    {
      return generatedPassword.stringValue();
    }
  }



  /**
   * Retrieves the binary representation of the generated password contained in
   * this extended result, if available.
   *
   * @return  The binary representation of the generated password contained in
   *          this extended result, or {@code null} if no generated password was
   *          included in the extended result.
   */
  @Nullable()
  public byte[] getGeneratedPasswordBytes()
  {
    if (generatedPassword == null)
    {
      return null;
    }
    else
    {
      return generatedPassword.getValue();
    }
  }



  /**
   * Retrieves the raw generated password contained in this extended result, if
   * available.
   *
   * @return  The raw generated password contained in this extended result, or
   *          {@code null} if no generated password was included in the extended
   *          result.
   */
  @Nullable()
  public ASN1OctetString getRawGeneratedPassword()
  {
    return generatedPassword;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_PASSWORD_MODIFY.get();
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
    buffer.append("PasswordModifyExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (generatedPassword != null)
    {
      buffer.append(", generatedPassword='*****REDACTED*****'");
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
