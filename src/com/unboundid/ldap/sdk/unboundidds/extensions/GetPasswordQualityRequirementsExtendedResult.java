/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Boolean;
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
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended result that can provide
 * information about the requirements that the server will enforce for
 * operations that change or replace a user's password, including adding a new
 * user, a user changing his/her own password, and an administrator resetting
 * another user's password.
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
 * If the get password quality request was processed successfully, then the
 * result will include an OID of 1.3.6.1.4.1.30221.2.6.44 and a value with the
 * following encoding:
 * <PRE>
 *   GetPasswordQualityRequirementsResultValue ::= SEQUENCE {
 *        requirements                SEQUENCE OF PasswordQualityRequirement,
 *        currentPasswordRequired     [0] BOOLEAN OPTIONAL,
 *        mustChangePassword          [1] BOOLEAN OPTIONAL,
 *        secondsUntilExpiration      [2] INTEGER OPTIONAL,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetPasswordQualityRequirementsExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.44) for the get password quality
   * requirements extended result.
   */
  @NotNull public static final String
       OID_GET_PASSWORD_QUALITY_REQUIREMENTS_RESULT =
            "1.3.6.1.4.1.30221.2.6.44";



  /**
   * The BER type for the current password required element.
   */
  private static final byte TYPE_CURRENT_PW_REQUIRED = (byte) 0x80;



  /**
   * The BER type for the must change password element.
   */
  private static final byte TYPE_MUST_CHANGE_PW = (byte) 0x81;



  /**
   * The BER type for the seconds until expiration element.
   */
  private static final byte TYPE_SECONDS_UNTIL_EXPIRATION = (byte) 0x82;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4990045432443188148L;



  // Indicates whether the user will be required to provide his/her current
  // password when performing the associated self password change.
  @Nullable private final Boolean currentPasswordRequired;

  // Indicates whether the user will be required to change his/her password
  // after performing the associated add or administrative reset.
  @Nullable private final Boolean mustChangePassword;

  // The length of time in seconds that the resulting password will be
  // considered valid.
  @Nullable private final Integer secondsUntilExpiration;

  // The list of password quality requirements that the server will enforce for
  // the associated operation.
  @NotNull private final List<PasswordQualityRequirement> passwordRequirements;



  /**
   * Creates a new get password quality requirements extended result with the
   * provided information.
   *
   * @param  messageID                The message ID for the LDAP message that
   *                                  is associated with this LDAP result.
   * @param  resultCode               The result code for the response.  This
   *                                  must not be {@code null}.
   * @param  diagnosticMessage        The diagnostic message for the response.
   *                                  This may be {@code null} if no diagnostic
   *                                  message is needed.
   * @param  matchedDN                The matched DN for the response.  This may
   *                                  be {@code null} if no matched DN is
   *                                  needed.
   * @param  referralURLs             The set of referral URLs from the
   *                                  response.  This may be {@code null} or
   *                                  empty if no referral URLs are needed.
   * @param  passwordRequirements     The password quality requirements for this
   *                                  result.  This must be {@code null} or
   *                                  empty if this result is for an operation
   *                                  that was not processed successfully.  It
   *                                  may be {@code null} or empty if the
   *                                  server will not enforce any password
   *                                  quality requirements for the target
   *                                  operation.
   * @param  currentPasswordRequired  Indicates whether the user will be
   *                                  required to provide his/her current
   *                                  password when performing a self change.
   *                                  This must be {@code null} if this result
   *                                  is for an operation that was not processed
   *                                  successfully or if the target operation is
   *                                  not a self change.
   * @param  mustChangePassword       Indicates whether the user will be
   *                                  required to change their password after
   *                                  the associated add or administrative
   *                                  reset before that user will be allowed to
   *                                  issue any other requests.  This must be
   *                                  {@code null} if this result is for an
   *                                  operation that was not processed
   *                                  successfully or if the target operation is
   *                                  not an add or an administrative reset.
   * @param  secondsUntilExpiration   Indicates the maximum length of time, in
   *                                  seconds, that the password set in the
   *                                  target operation will be valid.  If
   *                                  {@code mustChangePassword} is {@code true}
   *                                  then this will indicate the length of time
   *                                  that the user has to change his/her
   *                                  password after the add/reset.  If
   *                                  {@code mustChangePassword} is {@code null}
   *                                  or {@code false} then this will indicate
   *                                  the length of time until the password
   *                                  expires.  This must be {@code null} if
   *                                  this result is for an operation that was
   *                                  not processed successfully, or if the new
   *                                  password will be valid indefinitely.
   * @param  controls                 The set of controls to include in the
   *                                  result.  It may be {@code null} or empty
   *                                  if no controls are needed.
   */
  public GetPasswordQualityRequirementsExtendedResult(final int messageID,
       @NotNull final ResultCode resultCode,
       @Nullable final String diagnosticMessage,
       @Nullable final String matchedDN,
       @Nullable final String[] referralURLs,
       @Nullable final Collection<PasswordQualityRequirement>
            passwordRequirements,
       @Nullable final Boolean currentPasswordRequired,
       @Nullable final Boolean mustChangePassword,
       @Nullable final Integer secondsUntilExpiration,
       @Nullable final Control... controls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         ((resultCode == ResultCode.SUCCESS)
              ? OID_GET_PASSWORD_QUALITY_REQUIREMENTS_RESULT
              : null),
         encodeValue(resultCode, passwordRequirements, currentPasswordRequired,
              mustChangePassword, secondsUntilExpiration),
         controls);

    if ((passwordRequirements == null) || passwordRequirements.isEmpty())
    {
      this.passwordRequirements = Collections.emptyList();
    }
    else
    {
      this.passwordRequirements = Collections.unmodifiableList(
           new ArrayList<>(passwordRequirements));
    }

    this.currentPasswordRequired = currentPasswordRequired;
    this.mustChangePassword      = mustChangePassword;
    this.secondsUntilExpiration  = secondsUntilExpiration;
  }



  /**
   * Creates a new get password quality requirements extended result from the
   * provided generic result.
   *
   * @param  r  The generic extended result to parse as a get password quality
   *            requirements result.
   *
   * @throws  LDAPException  If the provided generic extended result cannot be
   *                         parsed as a get password quality requirements
   *                         result.
   */
  public GetPasswordQualityRequirementsExtendedResult(
              @NotNull final ExtendedResult r)
         throws LDAPException
  {
    super(r);

    final ASN1OctetString value = r.getValue();
    if (value == null)
    {
      passwordRequirements = Collections.emptyList();
      currentPasswordRequired = null;
      mustChangePassword = null;
      secondsUntilExpiration = null;
      return;
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();

      final ASN1Element[] requirementElements =
           ASN1Sequence.decodeAsSequence(elements[0]).elements();
      final ArrayList<PasswordQualityRequirement> requirementList =
           new ArrayList<>(requirementElements.length);
      for (final ASN1Element e : requirementElements)
      {
        requirementList.add(PasswordQualityRequirement.decode(e));
      }
      passwordRequirements = Collections.unmodifiableList(requirementList);

      Boolean cpr = null;
      Boolean mcp = null;
      Integer sue = null;
      for (int i=1; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_CURRENT_PW_REQUIRED:
            cpr = ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_MUST_CHANGE_PW:
            mcp = ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_SECONDS_UNTIL_EXPIRATION:
            sue = ASN1Integer.decodeAsInteger(elements[i]).intValue();
            break;

          default:
            // We may update this extended operation in the future to provide
            // support for returning additional password-related information.
            // If we encounter an unrecognized element, just ignore it rather
            // than throwing an exception.
            break;
        }
      }

      currentPasswordRequired = cpr;
      mustChangePassword = mcp;
      secondsUntilExpiration = sue;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_PW_QUALITY_REQS_RESULT_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value for this extended result, if appropriate.
   *
   * @param  resultCode               The result code for the response.  This
   *                                  must not be {@code null}.
   * @param  passwordRequirements     The password quality requirements for this
   *                                  result.  This must be {@code null} or
   *                                  empty if this result is for an operation
   *                                  that was not processed successfully.  It
   *                                  may be {@code null} or empty if the
   *                                  server will not enforce any password
   *                                  quality requirements for the target
   *                                  operation.
   * @param  currentPasswordRequired  Indicates whether the user will be
   *                                  required to provide his/her current
   *                                  password when performing a self change.
   *                                  This must be {@code null} if this result
   *                                  is for an operation that was not processed
   *                                  successfully or if the target operation is
   *                                  not a self change.
   * @param  mustChangePassword       Indicates whether the user will be
   *                                  required to change their password after
   *                                  the associated add or administrative
   *                                  reset before that user will be allowed to
   *                                  issue any other requests.  This must be
   *                                  {@code null} if this result is for an
   *                                  operation that was not processed
   *                                  successfully or if the target operation is
   *                                  not an add or an administrative reset.
   * @param  secondsUntilExpiration   Indicates the maximum length of time, in
   *                                  seconds, that the password set in the
   *                                  target operation will be valid.  If
   *                                  {@code mustChangePassword} is {@code true}
   *                                  then this will indicate the length of time
   *                                  that the user has to change his/her
   *                                  password after the add/reset.  If
   *                                  {@code mustChangePassword} is {@code null}
   *                                  or {@code false} then this will indicate
   *                                  the length of time until the password
   *                                  expires.  This must be {@code null} if
   *                                  this result is for an operation that was
   *                                  not processed successfully, or if the new
   *                                  password will be valid indefinitely.
   *
   * @return  The ASN.1 element with the encoded result value, or {@code null}
   *          if the result should not have a value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
       @NotNull final ResultCode resultCode,
       @Nullable final Collection<PasswordQualityRequirement>
            passwordRequirements,
       @Nullable final Boolean currentPasswordRequired,
       @Nullable final Boolean mustChangePassword,
       @Nullable final Integer secondsUntilExpiration)
  {
    if (resultCode != ResultCode.SUCCESS)
    {
      Validator.ensureTrue((passwordRequirements == null) ||
           passwordRequirements.isEmpty());
      Validator.ensureTrue(currentPasswordRequired == null);
      Validator.ensureTrue(mustChangePassword == null);
      Validator.ensureTrue(secondsUntilExpiration == null);

      return null;
    }

    final ArrayList<ASN1Element> valueSequence = new ArrayList<>(4);

    if (passwordRequirements == null)
    {
      valueSequence.add(new ASN1Sequence());
    }
    else
    {
      final ArrayList<ASN1Element> requirementElements =
           new ArrayList<>(passwordRequirements.size());
      for (final PasswordQualityRequirement r : passwordRequirements)
      {
        requirementElements.add(r.encode());
      }
      valueSequence.add(new ASN1Sequence(requirementElements));
    }

    if (currentPasswordRequired != null)
    {
      valueSequence.add(new ASN1Boolean(TYPE_CURRENT_PW_REQUIRED,
           currentPasswordRequired));
    }

    if (mustChangePassword != null)
    {
      valueSequence.add(new ASN1Boolean(TYPE_MUST_CHANGE_PW,
           mustChangePassword));
    }

    if (secondsUntilExpiration != null)
    {
      valueSequence.add(new ASN1Integer(TYPE_SECONDS_UNTIL_EXPIRATION,
           secondsUntilExpiration));
    }

    return new ASN1OctetString(new ASN1Sequence(valueSequence).encode());
  }



  /**
   * Retrieves the list of password quality requirements that specify the
   * constraints that a proposed password must satisfy in order to be accepted
   * by the server in an operation of the type specified in the get password
   * quality requirements request.
   *
   * @return  A list of the password quality requirements returned by the
   *          server, or an empty list if this result is for a non-successful
   *          get password quality requirements operation or if the server
   *          will not impose any password quality requirements for the
   *          specified operation type.
   */
  @NotNull()
  public List<PasswordQualityRequirement> getPasswordRequirements()
  {
    return passwordRequirements;
  }



  /**
   * Retrieves a flag that indicates whether the target user will be required to
   * provide his/her current password in order to set a new password with a self
   * change.
   *
   * @return  A value of {@code Boolean.TRUE} if the target operation is a self
   *          change and the user will be required to provide his/her current
   *          password when setting a new one, {@code Boolean.FALSE} if the
   *          target operation is a self change and the user will not be
   *          required to provide his/her current password, or {@code null} if
   *          the target operation is not a self change or if this result is for
   *          a non-successful get password quality requirements operation.
   */
  @Nullable()
  public Boolean getCurrentPasswordRequired()
  {
    return currentPasswordRequired;
  }



  /**
   * Retrieves a flag that indicates whether the target user will be required to
   * immediately change his/her own password after the associated add or
   * administrative reset operation before that user will be allowed to issue
   * any other types of requests.
   *
   * @return  A value of {@code Boolean.TRUE} if the target operation is an add
   *          or administrative reset and the user will be required to
   *          immediately perform a self change to select a new password before
   *          being allowed to perform any other kinds of operations,
   *          {@code Boolean.FALSE} if the target operation is an add or
   *          administrative reset but the user will not be required to
   *          immediately select a new password with a self change, or
   *          {@code null} if the target operation is not an add or
   *          administrative reset, or if this result is for a non-successful
   *          get password quality requirements operation.
   */
  @Nullable()
  public Boolean getMustChangePassword()
  {
    return mustChangePassword;
  }



  /**
   * Retrieves the length of time, in seconds, that the new password will be
   * considered valid after the change is applied.  If the associated operation
   * is an add or an administrative reset and {@link #getMustChangePassword()}
   * returns {@code Boolean.TRUE}, then this will indicate the length of time
   * that the user has to choose a new password with a self change before the
   * account becomes locked.  If the associated operation is a self change, or
   * if {@code getMustChangePassword} returns {@code Boolean.FALSE}, then this
   * will indicate the maximum length of time that the newly-selected password
   * may be used until it expires.
   *
   * @return  The length of time, in seconds, that the new password will be
   *          considered valid after the change is applied, or {@code null} if
   *          this result is for a non-successful get password quality
   *          requirements operation or if the newly-selected password can be
   *          used indefinitely.
   */
  @Nullable()
  public Integer getSecondsUntilExpiration()
  {
    return secondsUntilExpiration;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_GET_PW_QUALITY_REQS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetPasswordQualityRequirementsExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    buffer.append(", requirements{");

    final Iterator<PasswordQualityRequirement> requirementsIterator =
         passwordRequirements.iterator();
    while (requirementsIterator.hasNext())
    {
      requirementsIterator.next().toString(buffer);
      if (requirementsIterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append('}');

    if (currentPasswordRequired != null)
    {
      buffer.append(", currentPasswordRequired=");
      buffer.append(currentPasswordRequired);
    }

    if (mustChangePassword != null)
    {
      buffer.append(", mustChangePassword=");
      buffer.append(mustChangePassword);
    }

    if (secondsUntilExpiration != null)
    {
      buffer.append(", secondsUntilExpiration=");
      buffer.append(secondsUntilExpiration);
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
