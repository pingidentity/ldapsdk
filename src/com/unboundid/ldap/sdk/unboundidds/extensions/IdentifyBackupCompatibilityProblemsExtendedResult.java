/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended result that can be used
 * to identify potential incompatibility problems between two backup
 * compatibility descriptor values.
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
 * The OID for this extended result is 1.3.6.1.4.1.30221.2.6.33.  If the request
 * was processed successfully, then the response will have a value with the
 * following encoding:
 * <PRE>
 *   IdentifyBackupCompatibilityProblemsResult ::= SEQUENCE {
 *        errorMessages       [0] SEQUENCE OF OCTET STRING OPTIONAL,
 *        warningMessages     [1] SEQUENCE OF OCTET STRING OPTIONAL,
 *        ... }
 * </PRE>
 *
 * @see  IdentifyBackupCompatibilityProblemsExtendedRequest
 * @see  GetBackupCompatibilityDescriptorExtendedRequest
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IdentifyBackupCompatibilityProblemsExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.33) for the identify backup compatibility
   * problems extended request.
   */
  @NotNull public static final String
       IDENTIFY_BACKUP_COMPATIBILITY_PROBLEMS_RESULT_OID =
            "1.3.6.1.4.1.30221.2.6.33";



  /**
   * The BER type for the error messages element in the value sequence.
   */
  private static final byte TYPE_ERRORS = (byte) 0xA0;



  /**
   * The BER type for the warning messages element in the value sequence.
   */
  private static final byte TYPE_WARNINGS = (byte) 0xA1;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6492859100961846933L;



  // The compatibility error messages.
  @NotNull private final List<String> errorMessages;

  // The compatibility warning messages.
  @NotNull private final List<String> warningMessages;



  /**
   * Creates a new identify backup compatibility problems extended result from
   * the provided generic extended result.
   *
   * @param  result  The generic extended result to be decoded as an identify
   *                 backup compatibility problems extended result.
   *
   * @throws LDAPException  If the provided extended result cannot be parsed as
   *                        a valid identify backup compatibility problems
   *                        extended result.
   */
  public IdentifyBackupCompatibilityProblemsExtendedResult(
              @NotNull final ExtendedResult result)
         throws LDAPException
  {
    super(result);

    final ASN1OctetString value = result.getValue();
    if (value == null)
    {
      errorMessages = Collections.emptyList();
      warningMessages = Collections.emptyList();
      return;
    }

    try
    {
      List<String> errors = Collections.emptyList();
      List<String> warnings = Collections.emptyList();
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      for (final ASN1Element e : elements)
      {
        switch (e.getType())
        {
          case TYPE_ERRORS:
            final ASN1Element[] errorElements =
                 ASN1Sequence.decodeAsSequence(e).elements();
            final ArrayList<String> errorStrings =
                 new ArrayList<>(errorElements.length);
            for (final ASN1Element errorElement : errorElements)
            {
              errorStrings.add(ASN1OctetString.decodeAsOctetString(
                   errorElement).stringValue());
            }
            errors = Collections.unmodifiableList(errorStrings);
            break;

          case TYPE_WARNINGS:
            final ASN1Element[] warningElements =
                 ASN1Sequence.decodeAsSequence(e).elements();
            final ArrayList<String> warningStrings =
                 new ArrayList<>(warningElements.length);
            for (final ASN1Element warningElement : warningElements)
            {
              warningStrings.add(ASN1OctetString.decodeAsOctetString(
                   warningElement).stringValue());
            }
            warnings = Collections.unmodifiableList(warningStrings);
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_IDENTIFY_BACKUP_COMPAT_PROBLEMS_RESULT_UNEXPECTED_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }

      errorMessages   = errors;
      warningMessages = warnings;
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
           ERR_GET_BACKUP_COMPAT_RESULT_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a new identify backup compatibility problems extended result with
   * the provided information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  errorMessages      The set of error messages to include in the
   *                            result.  It may be {@code null} or empty if no
   *                            error messages should be included.
   * @param  warningMessages    The set of warning messages to include in the
   *                            result.  It may be {@code null} or empty if no
   *                            warning messages should be included.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public IdentifyBackupCompatibilityProblemsExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final Collection<String> errorMessages,
              @Nullable final Collection<String> warningMessages,
              @Nullable final Control... responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         ((resultCode == ResultCode.SUCCESS)
              ? IDENTIFY_BACKUP_COMPATIBILITY_PROBLEMS_RESULT_OID
              : null),
         encodeValue(resultCode, errorMessages, warningMessages),
         responseControls);

    if (errorMessages == null)
    {
      this.errorMessages = Collections.emptyList();
    }
    else
    {
      this.errorMessages =
           Collections.unmodifiableList(new ArrayList<>(errorMessages));
    }

    if (warningMessages == null)
    {
      this.warningMessages = Collections.emptyList();
    }
    else
    {
      this.warningMessages =
           Collections.unmodifiableList(new ArrayList<>(warningMessages));
    }
  }



  /**
   * Creates an ASN.1 octet string containing an encoded representation of the
   * value for an identify backup compatibility problems extended result with
   * the provided information.
   *
   * @param  resultCode       The result code from the response.
   * @param  errorMessages    The set of error messages to include in the
   *                          result.  It may be {@code null} or empty if no
   *                          error messages should be included.
   * @param  warningMessages  The set of warning messages to include in the
   *                          result.  It may be {@code null} or empty if no
   *                          warning messages should be included.
   *
   * @return  An ASN.1 octet string containing an encoded representation of the
   *          value for an identify backup compatibility problems extended
   *          result, or {@code null} if a result with the provided information
   *          should not have a value.
   */
  @Nullable()
  public static ASN1OctetString encodeValue(
              @NotNull final ResultCode resultCode,
              @Nullable final Collection<String> errorMessages,
              @Nullable final Collection<String> warningMessages)
  {
    if (resultCode != ResultCode.SUCCESS)
    {
      Validator.ensureTrue(
           (((errorMessages == null) || errorMessages.isEmpty()) &&
            ((warningMessages == null) || warningMessages.isEmpty())),
           "There must not be any warning or error messages with a " +
                "non-success result.");
      return null;
    }

    final ArrayList<ASN1Element> elements = new ArrayList<>(2);

    if ((errorMessages != null) && (! errorMessages.isEmpty()))
    {
      final ArrayList<ASN1Element> msgElements =
           new ArrayList<>(errorMessages.size());
      for (final String s : errorMessages)
      {
        msgElements.add(new ASN1OctetString(s));
      }
      elements.add(new ASN1Sequence(TYPE_ERRORS, msgElements));
    }

    if ((warningMessages != null) && (! warningMessages.isEmpty()))
    {
      final ArrayList<ASN1Element> msgElements =
           new ArrayList<>(warningMessages.size());
      for (final String s : warningMessages)
      {
        msgElements.add(new ASN1OctetString(s));
      }
      elements.add(new ASN1Sequence(TYPE_WARNINGS, msgElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves a list of messages for any compatibility errors that have been
   * identified.  If there are any errors, a backup from the source cannot be
   * restored into the target.
   *
   * @return  A list of messages for any compatibility errors that have been
   *          identified, or an empty list if there are no compatibility errors.
   */
  @NotNull()
  public List<String> getErrorMessages()
  {
    return errorMessages;
  }



  /**
   * Retrieves a list of messages for any compatibility warnings that have been
   * identified.  If there are any warnings, it may still be possible to restore
   * a backup from the source into the target.
   *
   * @return  A list of messages for any compatibility warnings that have been
   *          identified, or an empty list if there are no compatibility
   *          warnings.
   */
  @NotNull()
  public List<String> getWarningMessages()
  {
    return warningMessages;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_IDENTIFY_BACKUP_COMPAT_PROBLEMS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("IdentifyBackupCompatibilityProblemsExtendedResult(" +
         "resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (! errorMessages.isEmpty())
    {
      buffer.append(", errorMessages={");

      final Iterator<String> iterator = errorMessages.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
    }

    if (! warningMessages.isEmpty())
    {
      buffer.append(", warningMessages={");

      final Iterator<String> iterator = warningMessages.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
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
