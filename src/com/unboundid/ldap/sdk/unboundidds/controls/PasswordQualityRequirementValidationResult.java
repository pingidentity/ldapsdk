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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.io.Serializable;
import java.util.ArrayList;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.PasswordQualityRequirement;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a data structure that holds information about the result
 * of attempting validation with a proposed password against a password quality
 * requirement.
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
 * If it appears in an LDAP protocol element (e.g., in a password validation
 * details response control), then the password quality validation result object
 * should have the following ASN.1 encoding:
 * <PRE>
 *   PasswordQualityRequirementValidationResult ::= SEQUENCE {
 *        passwordRequirement      PasswordQualityRequirement,
 *        requirementSatisfied     BOOLEAN,
 *        additionalInfo           [0] OCTET STRING OPTIONAL }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordQualityRequirementValidationResult
       implements Serializable
{
  /**
   * The BER type for the additional info element of the value sequence.
   */
  private static final byte TYPE_ADDITIONAL_INFO = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8048878239770726375L;



  // Indicates whether the proposed password satisfied the constraints of the
  // associated password quality requirement.
  private final boolean requirementSatisfied;

  // The password quality requirement to which this validation result applies.
  @NotNull private final PasswordQualityRequirement passwordRequirement;

  // An optional message with additional information about the result of the
  // validation for the proposed password with respect to the associated
  // password quality requirement.
  @Nullable private final String additionalInfo;



  /**
   * Creates a new password quality requirement validation result object with
   * the provided information.
   *
   * @param  passwordRequirement   The password quality requirement to which
   *                               this validation result applies.  This must
   *                               not be {@code null}.
   * @param  requirementSatisfied  Indicates whether the proposed password
   *                               satisfied the constraints of the associated
   *                               password quality requirement.
   * @param  additionalInfo        An optional message with additional
   *                               information about the result of the
   *                               validation for the proposed password with
   *                               respect to the associated password quality
   *                               requirement.
   */
  public PasswordQualityRequirementValidationResult(
              @NotNull final PasswordQualityRequirement passwordRequirement,
              final boolean requirementSatisfied,
              @Nullable final String additionalInfo)
  {
    Validator.ensureNotNull(passwordRequirement);

    this.passwordRequirement  = passwordRequirement;
    this.requirementSatisfied = requirementSatisfied;
    this.additionalInfo       = additionalInfo;
  }



  /**
   * Retrieves the password quality requirement to which this validation result
   * applies.
   *
   * @return  The password quality requirement to which this validation result
   * applies.
   */
  @NotNull()
  public PasswordQualityRequirement getPasswordRequirement()
  {
    return passwordRequirement;
  }



  /**
   * Indicates whether the proposed password satisfied the constraints of the
   * associated password quality requirement.
   *
   * @return  {@code true} if the proposed password satisfied the constraints of
   *          the associated password quality requirement, or {@code false} if
   *          not.
   */
  public boolean requirementSatisfied()
  {
    return requirementSatisfied;
  }



  /**
   * Retrieves a message with additional information about the result of the
   * validation of the proposed password with respect to the associated
   * password quality requirement.
   *
   * @return  A message with additional information about the result of the
   *          validation, or {@code null} if no additional information is
   *          available.
   */
  @Nullable()
  public String getAdditionalInfo()
  {
    return additionalInfo;
  }



  /**
   * Encodes this password quality requirement validation result object to an
   * ASN.1 element.
   *
   * @return  The ASN.1 element that provides an encoded representation of this
   *          object.
   */
  @NotNull()
  public ASN1Element encode()
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(3);
    elements.add(passwordRequirement.encode());
    elements.add(new ASN1Boolean(requirementSatisfied));

    if (additionalInfo != null)
    {
      elements.add(new ASN1OctetString(TYPE_ADDITIONAL_INFO, additionalInfo));
    }

    return new ASN1Sequence(elements);
  }



  /**
   * Decodes the provided ASN.1 element as a password quality requirement
   * validation result.
   *
   * @param  element  The ASN.1 element to be decoded as a password quality
   *                  requirement validation result.
   *
   * @return  The ASN.1 element containing the encoded password quality
   *          requirement validation result.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the provided ASN.1 element.
   */
  @NotNull()
  public static PasswordQualityRequirementValidationResult decode(
                     @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(element).elements();
      final PasswordQualityRequirement passwordRequirement =
           PasswordQualityRequirement.decode(elements[0]);
      final boolean requirementSatisfied =
           ASN1Boolean.decodeAsBoolean(elements[1]).booleanValue();

      String additionalInfo = null;
      for (int i=2; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_ADDITIONAL_INFO:
            additionalInfo =
                 ASN1OctetString.decodeAsOctetString(elements[i]).stringValue();
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_PW_REQ_VALIDATION_RESULT_INVALID_ELEMENT_TYPE.get(
                      StaticUtils.toHex(elements[i].getType())));
        }
      }

      return new PasswordQualityRequirementValidationResult(passwordRequirement,
           requirementSatisfied, additionalInfo);
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
           ERR_PW_REQ_VALIDATION_RESULT_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves a string representation of this password quality requirement
   * validation result.
   *
   * @return  A string representation of this password quality requirement
   *          validation result.
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
   * Appends a string representation of this password quality requirement
   * validation result to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PasswordQualityRequirementValidationResult(requirement=");
    passwordRequirement.toString(buffer);
    buffer.append(", requirementSatisfied=");
    buffer.append(requirementSatisfied);

    if (additionalInfo != null)
    {
      buffer.append(", additionalInfo='");
      buffer.append(additionalInfo);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
