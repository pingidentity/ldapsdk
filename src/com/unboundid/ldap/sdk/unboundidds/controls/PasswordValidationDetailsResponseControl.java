/*
 * Copyright 2015-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2024 Ping Identity Corporation
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
 * Copyright (C) 2015-2024 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Null;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.PasswordQualityRequirement;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation for a response control that can be
 * returned by the server in the response for add, modify, and password modify
 * requests that include the password validation details request control.  This
 * response control will provide details about the password quality requirements
 * that are in effect for the operation and whether the password included in the
 * request satisfies each of those requirements.
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
 * This response control has an OID of 1.3.6.1.4.1.30221.2.5.41, a criticality
 * of {@code false}, and a value with the provided encoding:
 * <PRE>
 *   PasswordValidationDetailsResponse ::= SEQUENCE {
 *        validationResult            CHOICE {
 *             validationDetails             [0] SEQUENCE OF
 *                  PasswordQualityRequirementValidationResult,
 *             noPasswordProvided            [1] NULL,
 *             multiplePasswordsProvided     [2] NULL,
 *             noValidationAttempted         [3] NULL,
 *             ... },
 *        missingCurrentPassword     [3] BOOLEAN DEFAULT FALSE,
 *        mustChangePassword         [4] BOOLEAN DEFAULT FALSE,
 *        secondsUntilExpiration     [5] INTEGER OPTIONAL,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordValidationDetailsResponseControl
       extends Control
       implements DecodeableControl
{
 /**
  * The OID (1.3.6.1.4.1.30221.2.5.41) for the password validation details
  * response control.
  */
 @NotNull public static final String PASSWORD_VALIDATION_DETAILS_RESPONSE_OID =
      "1.3.6.1.4.1.30221.2.5.41";



  /**
   * The BER type for the missing current password element.
   */
  private static final byte TYPE_MISSING_CURRENT_PASSWORD = (byte) 0x83;



  /**
   * The BER type for the must change password element.
   */
  private static final byte TYPE_MUST_CHANGE_PW = (byte) 0x84;



  /**
   * The BER type for the seconds until expiration element.
   */
  private static final byte TYPE_SECONDS_UNTIL_EXPIRATION = (byte) 0x85;



  /**
   * The name of the field used to hold an additional information string in the
   * JSON representation of this control.
   */
  @NotNull private static final String
       JSON_FIELD_ADDITIONAL_INFORMATION = "additional-information";



  /**
   * The name of the field used to hold the set of client-side validation
   * properties in the JSON representation of this control.
   */
  @NotNull private static final String
       JSON_FIELD_CLIENT_SIDE_VALIDATION_PROPERTIES =
            "client-side-validation-properties";



  /**
   * The name of the field used to hold a client-side validation type in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_CLIENT_SIDE_VALIDATION_TYPE =
       "client-side-validation-type";



  /**
   * The name of the field used to hold a description in the JSON representation
   * of this control.
   */
  @NotNull private static final String JSON_FIELD_DESCRIPTION = "description";



  /**
   * The name of the field used to hold the missing current password flag in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_MISSING_CURRENT_PASSWORD =
       "missing-current-password";



  /**
   * The name of the field used to hold the must change password flag in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_MUST_CHANGE_PASSWORD =
       "must-change-password";



  /**
   * The name of the field used to hold a password quality requirement in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT =
       "password-quality-requirement";



  /**
   * The name of the field used to hold a property name in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_PROPERTY_NAME = "name";



  /**
   * The name of the field used to hold a property value in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_PROPERTY_VALUE = "value";



  /**
   * The name of the field used to indicate whether a password quality
   * requirement was satisfied in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_REQUIREMENT_SATISFIED =
       "requirement-satisfied";



  /**
   * The name of the field used to hold the response type in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_RESPONSE_TYPE =
       "response-type";



  /**
   * The name of the field used to hold the seconds until expiration in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SECONDS_UNTIL_EXPIRATION =
       "seconds-until-expiration";



  /**
   * The name of the field used to hold validation details objects in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_VALIDATION_DETAILS =
       "validation-details";



  /**
   * The multiple-passwords-provided response type value in the JSON
   * representation of this control.
   */
  @NotNull private static final String
       JSON_RESPONSE_TYPE_MULTIPLE_PASSWORDS_PROVIDED =
            "multiple-passwords-provided";



  /**
   * The no-password-provided response type value in the JSON representation of
   * this control.
   */
  @NotNull private static final String JSON_RESPONSE_TYPE_NO_PASSWORD_PROVIDED =
       "no-password-provided";



  /**
   * The no-validation-attempted response type value in the JSON representation
   * of this control.
   */
  @NotNull private static final String
       JSON_RESPONSE_TYPE_NO_VALIDATION_ATTEMPTED = "no-validation-attempted";



  /**
   * The validation-performed response type value in the JSON representation of
   * this control.
   */
  @NotNull private static final String JSON_RESPONSE_TYPE_VALIDATION_PERFORMED =
       "validation-performed";



 /**
  * The serial version UID for this serializable class.
  */
 private static final long serialVersionUID = -2205640814914704074L;



  // Indicates whether the associated password self change operation failed
  // (or would fail if attempted without validation errors) because the user is
  // required to provide his/her current password when performing a self change
  // but did not do so.
  private final boolean missingCurrentPassword;

  // Indicates whether the user will be required to change his/her password
  // immediately after the associated add or administrative password reset is
  // complete.
  private final boolean mustChangePassword;

  // The length of time in seconds that the new password will be considered
  // valid.
  @Nullable private final Integer secondsUntilExpiration;

  // The list of the validation results for the associated operation.
  @NotNull private final List<PasswordQualityRequirementValidationResult>
      validationResults;

  // The response type for this password validation details response control.
  @NotNull private final PasswordValidationDetailsResponseType responseType;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  PasswordValidationDetailsResponseControl()
  {
    responseType = null;
    validationResults = null;
    missingCurrentPassword = true;
    mustChangePassword = true;
    secondsUntilExpiration = null;
  }



  /**
   * Creates a password validation details response control with the provided
   * information.
   *
   * @param  responseType            The response type for this password
   *                                 validation details response control.  This
   *                                 must not be {@code null}.
   * @param  validationResults       A list of the results obtained when
   *                                 validating the password against the
   *                                 password quality requirements.  This must
   *                                 be {@code null} or empty if the
   *                                 {@code responseType} element has a value
   *                                 other than {@code VALIDATION_DETAILS}.
   * @param  missingCurrentPassword  Indicates whether the associated operation
   *                                 is a self change that failed (or would have
   *                                 failed if not for additional validation
   *                                 failures) because the user did not provide
   *                                 his/her current password as required.
   * @param  mustChangePassword      Indicates whether the associated operation
   *                                 is an add or administrative reset that will
   *                                 require the user to change his/her password
   *                                 immediately after authenticating before
   *                                 allowing them to perform any other
   *                                 operation in the server.
   * @param  secondsUntilExpiration  The maximum length of time, in seconds,
   *                                 that the newly-set password will be
   *                                 considered valid.  This may be {@code null}
   *                                 if the new password will be considered
   *                                 valid indefinitely.
   */
  public PasswordValidationDetailsResponseControl(
       @NotNull final PasswordValidationDetailsResponseType responseType,
       @Nullable final Collection<PasswordQualityRequirementValidationResult>
            validationResults,
       final boolean missingCurrentPassword,
       final boolean mustChangePassword,
       @Nullable final Integer secondsUntilExpiration)
  {
    super(PASSWORD_VALIDATION_DETAILS_RESPONSE_OID, false,
         encodeValue(responseType, validationResults, missingCurrentPassword,
              mustChangePassword, secondsUntilExpiration));

    this.responseType           = responseType;
    this.missingCurrentPassword = missingCurrentPassword;
    this.mustChangePassword     = mustChangePassword;
    this.secondsUntilExpiration = secondsUntilExpiration;

    if (validationResults == null)
    {
      this.validationResults = Collections.emptyList();
    }
    else
    {
      this.validationResults = Collections.unmodifiableList(
           new ArrayList<>(validationResults));
    }
  }



  /**
   * Creates a new password validation details response control by decoding the
   * provided generic control information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be considered
   *                     critical.
   * @param  value       The value for the control.
   *
   * @throws  LDAPException  If the provided information cannot be decoded to
   *                         create a password validation details response
   *                         control.
   */
  public PasswordValidationDetailsResponseControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_VALIDATION_RESPONSE_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();

      responseType = PasswordValidationDetailsResponseType.forBERType(
           elements[0].getType());
      if (responseType == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PW_VALIDATION_RESPONSE_INVALID_RESPONSE_TYPE.get(
                  StaticUtils.toHex(elements[0].getType())));
      }

      if (responseType ==
          PasswordValidationDetailsResponseType.VALIDATION_DETAILS)
      {
        final ASN1Element[] resultElements =
             ASN1Sequence.decodeAsSequence(elements[0]).elements();

        final ArrayList<PasswordQualityRequirementValidationResult> resultList =
             new ArrayList<>(resultElements.length);
        for (final ASN1Element e : resultElements)
        {
          resultList.add(PasswordQualityRequirementValidationResult.decode(e));
        }
        validationResults = Collections.unmodifiableList(resultList);
      }
      else
      {
        validationResults = Collections.emptyList();
      }

      boolean missingCurrent = false;
      boolean mustChange = false;
      Integer secondsRemaining = null;
      for (int i=1; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_MISSING_CURRENT_PASSWORD:
            missingCurrent =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_MUST_CHANGE_PW:
            mustChange =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_SECONDS_UNTIL_EXPIRATION:
            secondsRemaining =
                 ASN1Integer.decodeAsInteger(elements[i]).intValue();
            break;

          default:
            // We may update this control in the future to provide support for
            // returning additional password-related information.  If we
            // encounter an unrecognized element, just ignore it rather than
            // throwing an exception.
            break;
        }
      }

      missingCurrentPassword = missingCurrent;
      mustChangePassword     = mustChange;
      secondsUntilExpiration = secondsRemaining;
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
           ERR_PW_VALIDATION_RESPONSE_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information to an ASN.1 element suitable for use as
   * the control value.
   *
   * @param  responseType            The response type for this password
   *                                 validation details response control.  This
   *                                 must not be {@code null}.
   * @param  validationResults       A list of the results obtained when
   *                                 validating the password against the
   *                                 password quality requirements.  This must
   *                                 be {@code null} or empty if the
   *                                 {@code responseType} element has a value
   *                                 other than {@code VALIDATION_DETAILS}.
   * @param  missingCurrentPassword  Indicates whether the associated operation
   *                                 is a self change that failed (or would have
   *                                 failed if not for additional validation
   *                                 failures) because the user did not provide
   *                                 his/her current password as required.
   * @param  mustChangePassword      Indicates whether the associated operation
   *                                 is an add or administrative reset that will
   *                                 require the user to change his/her password
   *                                 immediately after authenticating before
   *                                 allowing them to perform any other
   *                                 operation in the server.
   * @param  secondsUntilExpiration  The maximum length of time, in seconds,
   *                                 that the newly-set password will be
   *                                 considered valid.  This may be {@code null}
   *                                 if the new password will be considered
   *                                 valid indefinitely.
   *
   * @return  The encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
       @NotNull final PasswordValidationDetailsResponseType responseType,
       @Nullable final Collection<PasswordQualityRequirementValidationResult>
            validationResults,
       final boolean missingCurrentPassword,
       final boolean mustChangePassword,
       @Nullable final Integer secondsUntilExpiration)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(4);

    switch (responseType)
    {
      case VALIDATION_DETAILS:
        if (validationResults == null)
        {
          elements.add(new ASN1Sequence(responseType.getBERType()));
        }
        else
        {
          final ArrayList<ASN1Element> resultElements =
               new ArrayList<>(validationResults.size());
          for (final PasswordQualityRequirementValidationResult r :
               validationResults)
          {
            resultElements.add(r.encode());
          }
          elements.add(new ASN1Sequence(responseType.getBERType(),
               resultElements));
        }
        break;

      case NO_PASSWORD_PROVIDED:
      case MULTIPLE_PASSWORDS_PROVIDED:
      case NO_VALIDATION_ATTEMPTED:
        elements.add(new ASN1Null(responseType.getBERType()));
        break;
    }

    if (missingCurrentPassword)
    {
      elements.add(new ASN1Boolean(TYPE_MISSING_CURRENT_PASSWORD,
           missingCurrentPassword));
    }

    if (mustChangePassword)
    {
      elements.add(new ASN1Boolean(TYPE_MUST_CHANGE_PW, mustChangePassword));
    }

    if (secondsUntilExpiration != null)
    {
      elements.add(new ASN1Integer(TYPE_SECONDS_UNTIL_EXPIRATION,
           secondsUntilExpiration));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the response type for this password validation details response
   * control.
   *
   * @return  The response type for this password validation details response
   *          control.
   */
  @NotNull()
  public PasswordValidationDetailsResponseType getResponseType()
  {
    return responseType;
  }



  /**
   * Retrieves a list of the results obtained when attempting to validate the
   * proposed password against the password quality requirements in effect for
   * the operation.
   *
   * @return  A list of the results obtained when attempting to validate the
   *          proposed password against the password quality requirements in
   *          effect for the operation, or an empty list if no validation
   *          results are available.
   */
  @NotNull()
  public List<PasswordQualityRequirementValidationResult> getValidationResults()
  {
    return validationResults;
  }



  /**
   * Indicates whether the associated operation is a self password change that
   * requires the user to provide his/her current password when setting a new
   * password, but no current password was provided.
   *
   * @return  {@code true} if the associated operation is a self password change
   *          that requires the user to provide his/her current password when
   *          setting a new password but none was required, or {@code false} if
   *          the associated operation was not a self change, or if the user's
   *          current password was provided.
   */
  public boolean missingCurrentPassword()
  {
    return missingCurrentPassword;
  }



  /**
   * Indicates whether the user will be required to immediately change his/her
   * password after the associated add or administrative reset is complete.
   *
   * @return  {@code true} if the associated operation is an add or
   *          administrative reset and the user will be required to change
   *          his/her password before being allowed to perform any other
   *          operation, or {@code false} if the associated operation was not am
   *          add or an administrative reset, or if the user will not be
   *          required to immediately change his/her password.
   */
  public boolean mustChangePassword()
  {
    return mustChangePassword;
  }



  /**
   * Retrieves the maximum length of time, in seconds, that the newly-set
   * password will be considered valid.  If {@link #mustChangePassword()}
   * returns {@code true}, then this value will be the length of time that the
   * user has to perform a self password change before the account becomes
   * locked.  If {@code mustChangePassword()} returns {@code false}, then this
   * value will be the length of time until the password expires.
   *
   * @return  The maximum length of time, in seconds, that the newly-set
   *          password will be considered valid, or {@code null} if the new
   *          password will be valid indefinitely.
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
  public PasswordValidationDetailsResponseControl decodeControl(
              @NotNull final String oid, final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new PasswordValidationDetailsResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts a password validation details response control from the provided
   * result.
   *
   * @param  result  The result from which to retrieve the password validation
   *                 details response control.
   *
   * @return  The password validation details response control contained in the
   *          provided result, or {@code null} if the result did not contain a
   *          password validation details response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the password validation details response
   *                         control contained in the provided result.
   */
  @Nullable()
  public static PasswordValidationDetailsResponseControl get(
                     @NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(PASSWORD_VALIDATION_DETAILS_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof PasswordValidationDetailsResponseControl)
    {
      return (PasswordValidationDetailsResponseControl) c;
    }
    else
    {
      return new PasswordValidationDetailsResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }



  /**
   * Extracts a password validation details response control from the provided
   * result.
   *
   * @param  exception  The exception that was thrown when trying to process the
   *                    associated operation.
   *
   * @return  The password validation details response control contained in the
   *          provided result, or {@code null} if the result did not contain a
   *          password validation details response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the password validation details response
   *                         control contained in the provided result.
   */
  @NotNull()
  public static PasswordValidationDetailsResponseControl get(
                     @NotNull final LDAPException exception)
         throws LDAPException
  {
    return get(exception.toLDAPResult());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PW_VALIDATION_RESPONSE.get();
  }



  /**
   * Retrieves a representation of this password validation details response
   * control as a JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the password validation details
   *     response control, the OID is "1.3.6.1.4.1.30221.2.5.41".
   *   </LI>
   *   <LI>
   *     {@code control-name} -- An optional string field whose value is a
   *     human-readable name for this control.  This field is only intended for
   *     descriptive purposes, and when decoding a control, the {@code oid}
   *     field should be used to identify the type of control.
   *   </LI>
   *   <LI>
   *     {@code criticality} -- A mandatory Boolean field used to indicate
   *     whether this control is considered critical.
   *   </LI>
   *   <LI>
   *     {@code value-base64} -- An optional string field whose value is a
   *     base64-encoded representation of the raw value for this password
   *     validation details response control.  Exactly one of the
   *     {@code value-base64} and {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this password validation
   *     details response control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code response-type} -- A string field that specifies the result
   *         of the password validation processing for the attempt.  The value
   *         will be one of "{@code validation-performed}",
   *         "{@code no-password-provided}",
   *         "{@code multiple-passwords-provided}", or
   *         "{@code no-validation-attempted}".
   *       </LI>
   *       <LI>
   *         {@code validation-details} -- An optional array field whose values
   *         are JSON objects with information about the types of validation
   *         performed for the new password.  The fields that may be used in
   *         these JSON objects include:
   *         <UL>
   *           <LI>
   *             {@code password-quality-requirement} -- A JSON object whose
   *             value provides information about a password quality requirement
   *             that was evaluated.  The fields used in these JSON objects
   *             include:
   *             <UL>
   *               <LI>
   *                 {@code description} -- A string field whose value is a
   *                 user-friendly description of the password quality
   *                 requirement.
   *               </LI>
   *               <LI>
   *                 {@code client-side-validation-type} -- An optional string
   *                 field whose value is an identifier that the client can use
   *                 to programmatically determine the type of requirement.
   *               </LI>
   *               <LI>
   *                 {@code client-side-validation-properties} -- An optional
   *                 array field whose values are JSON objects with additional
   *                 properties that the client can use in the course of
   *                 programmatically determining whether a proposed password is
   *                 likely to satisfy the requirement.  Each of these JSON
   *                 objects will include a {@code name} field whose value is a
   *                 string that specifies the property name, and a
   *                 {@code value} field whose value is a string that specifies
   *                 the property value.
   *               </LI>
   *             </UL>
   *           </LI>
   *           <LI>
   *             {@code requirement-satisfied} -- A Boolean field that indicates
   *             whether the provided new password satisfies the password
   *             quality requirement.
   *           </LI>
   *           <LI>
   *             {@code additional-information} -- An optional string field
   *             whose value provides additional information about the
   *             validation for the associated requirement.
   *           </LI>
   *         </UL>
   *       </LI>
   *       <LI>
   *         {@code missing-current-password} -- A Boolean field that indicates
   *         whether the server requires the user's current password to be
   *         provided when choosing a new password, but that password was not
   *         provided.
   *       </LI>
   *       <LI>
   *         {@code must-change-password} -- A Boolean field that indicates
   *         whether the user will be required to choose a new password before
   *         they will be allowed to request any other operations.
   *       </LI>
   *       <LI>
   *         {@code seconds-until-expiration} -- An optional integer field whose
   *         value is the number of seconds until the new password will
   *         expire.
   *       </LI>
   *     </UL>
   *   </LI>
   * </UL>
   *
   * @return  A JSON object that contains a representation of this control.
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    final Map<String,JSONValue> valueFields = new LinkedHashMap<>();

    switch (responseType)
    {
      case VALIDATION_DETAILS:
        valueFields.put(JSON_FIELD_RESPONSE_TYPE,
             new JSONString(JSON_RESPONSE_TYPE_VALIDATION_PERFORMED));

        final List<JSONValue> validationDetailsValues =
             new ArrayList<>(validationResults.size());
        for (final PasswordQualityRequirementValidationResult result :
             validationResults)
        {
          validationDetailsValues.add(encodeValidationResultJSON(result));
        }
        valueFields.put(JSON_FIELD_VALIDATION_DETAILS,
        new JSONArray(validationDetailsValues));
        break;

      case NO_PASSWORD_PROVIDED:
        valueFields.put(JSON_FIELD_RESPONSE_TYPE,
             new JSONString(JSON_RESPONSE_TYPE_NO_PASSWORD_PROVIDED));
        break;

      case MULTIPLE_PASSWORDS_PROVIDED:
        valueFields.put(JSON_FIELD_RESPONSE_TYPE,
             new JSONString(JSON_RESPONSE_TYPE_MULTIPLE_PASSWORDS_PROVIDED));
        break;

      case NO_VALIDATION_ATTEMPTED:
        valueFields.put(JSON_FIELD_RESPONSE_TYPE,
             new JSONString(JSON_RESPONSE_TYPE_NO_VALIDATION_ATTEMPTED));
        break;
    }

    valueFields.put(JSON_FIELD_MISSING_CURRENT_PASSWORD,
         new JSONBoolean(missingCurrentPassword));

    valueFields.put(JSON_FIELD_MUST_CHANGE_PASSWORD,
         new JSONBoolean(mustChangePassword));

    if (secondsUntilExpiration != null)
    {
      valueFields.put(JSON_FIELD_SECONDS_UNTIL_EXPIRATION,
           new JSONNumber(secondsUntilExpiration));
    }

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              PASSWORD_VALIDATION_DETAILS_RESPONSE_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_PW_VALIDATION_RESPONSE.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(valueFields)));
  }



  /**
   * Encodes the provided password quality requirement validation result to a
   * JSON object.
   *
   * @param  result  The result to be encoded.  It must not be {@code null}.
   *
   * @return  A JSON object containing the encoded result.
   */
  @NotNull()
  private static JSONObject encodeValidationResultJSON(
               @NotNull final PasswordQualityRequirementValidationResult result)
  {
    final PasswordQualityRequirement requirement =
         result.getPasswordRequirement();
    final Map<String,JSONValue> requirementFields = new LinkedHashMap<>();

    requirementFields.put(JSON_FIELD_DESCRIPTION,
         new JSONString(requirement.getDescription()));

    final String clientSideValidationType =
         requirement.getClientSideValidationType();
    if (clientSideValidationType != null)
    {
      requirementFields.put(JSON_FIELD_CLIENT_SIDE_VALIDATION_TYPE,
           new JSONString(clientSideValidationType));
    }

    final Map<String,String> clientSideValidationProperties =
         requirement.getClientSideValidationProperties();
    if (! clientSideValidationProperties.isEmpty())
    {
      final List<JSONValue> propertyValues =
           new ArrayList<>(clientSideValidationProperties.size());
      for (final Map.Entry<String,String> e :
           clientSideValidationProperties.entrySet())
      {
        propertyValues.add(new JSONObject(
             new JSONField(JSON_FIELD_PROPERTY_NAME, e.getKey()),
             new JSONField(JSON_FIELD_PROPERTY_VALUE, e.getValue())));
      }

      requirementFields.put(JSON_FIELD_CLIENT_SIDE_VALIDATION_PROPERTIES,
           new JSONArray(propertyValues));
    }


    final Map<String,JSONValue> detailsFields = new LinkedHashMap<>();

    detailsFields.put(JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT,
         new JSONObject(requirementFields));

    detailsFields.put(JSON_FIELD_REQUIREMENT_SATISFIED,
         new JSONBoolean(result.requirementSatisfied()));

    final String additionalInformation = result.getAdditionalInfo();
    if (additionalInformation != null)
    {
      detailsFields.put(JSON_FIELD_ADDITIONAL_INFORMATION,
           new JSONString(additionalInformation));
    }

    return new JSONObject(detailsFields);
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * password validation details response control.
   *
   * @param  controlObject  The JSON object to be decoded.  It must not be
   *                        {@code null}.
   * @param  strict         Indicates whether to use strict mode when decoding
   *                        the provided JSON object.  If this is {@code true},
   *                        then this method will throw an exception if the
   *                        provided JSON object contains any unrecognized
   *                        fields.  If this is {@code false}, then unrecognized
   *                        fields will be ignored.
   *
   * @return  The password validation details response control that was decoded
   *          from the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid password validation details response control.
   */
  @NotNull()
  public static PasswordValidationDetailsResponseControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new PasswordValidationDetailsResponseControl(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue);
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final String responseTypeStr =
         valueObject.getFieldAsString(JSON_FIELD_RESPONSE_TYPE);
    if (responseTypeStr == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_VALIDATION_RESPONSE_JSON_VALUE_MISSING_FIELD.get(
                controlObject.toSingleLineString(), JSON_FIELD_RESPONSE_TYPE));
    }

    final PasswordValidationDetailsResponseType responseType;
    switch (responseTypeStr)
    {
      case JSON_RESPONSE_TYPE_VALIDATION_PERFORMED:
        responseType = PasswordValidationDetailsResponseType.VALIDATION_DETAILS;
        break;
      case JSON_RESPONSE_TYPE_NO_PASSWORD_PROVIDED:
        responseType =
             PasswordValidationDetailsResponseType.NO_PASSWORD_PROVIDED;
        break;
      case JSON_RESPONSE_TYPE_MULTIPLE_PASSWORDS_PROVIDED:
        responseType =
             PasswordValidationDetailsResponseType.MULTIPLE_PASSWORDS_PROVIDED;
        break;
      case JSON_RESPONSE_TYPE_NO_VALIDATION_ATTEMPTED:
        responseType =
             PasswordValidationDetailsResponseType.NO_VALIDATION_ATTEMPTED;
        break;
      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PW_VALIDATION_RESPONSE_JSON_UNKNOWN_RESPONSE_TYPE.get(
                  controlObject.toSingleLineString(), JSON_FIELD_RESPONSE_TYPE,
                  responseTypeStr));
    }


    final List<PasswordQualityRequirementValidationResult> validationResults;
    final List<JSONValue> validationDetailsValues =
         valueObject.getFieldAsArray(JSON_FIELD_VALIDATION_DETAILS);
    if (validationDetailsValues == null)
    {
      validationResults = Collections.emptyList();
    }
    else
    {
      validationResults = new ArrayList<>(validationDetailsValues.size());
      for (final JSONValue v : validationDetailsValues)
      {
        validationResults.add(decodeValidationResultJSON(controlObject, v,
             strict));
      }
    }


    final Boolean missingCurrentPassword =
         valueObject.getFieldAsBoolean(JSON_FIELD_MISSING_CURRENT_PASSWORD);
    if (missingCurrentPassword == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_VALIDATION_RESPONSE_JSON_VALUE_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_MISSING_CURRENT_PASSWORD));
    }


    final Boolean mustChangePassword =
         valueObject.getFieldAsBoolean(JSON_FIELD_MUST_CHANGE_PASSWORD);
    if (mustChangePassword == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_VALIDATION_RESPONSE_JSON_VALUE_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_MUST_CHANGE_PASSWORD));
    }


    final Integer secondsUntilExpiration =
         valueObject.getFieldAsInteger(JSON_FIELD_SECONDS_UNTIL_EXPIRATION);


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_RESPONSE_TYPE,
                JSON_FIELD_VALIDATION_DETAILS,
                JSON_FIELD_MISSING_CURRENT_PASSWORD,
                JSON_FIELD_MUST_CHANGE_PASSWORD,
                JSON_FIELD_SECONDS_UNTIL_EXPIRATION);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PW_VALIDATION_RESPONSE_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new PasswordValidationDetailsResponseControl(responseType,
         validationResults, missingCurrentPassword, mustChangePassword,
         secondsUntilExpiration);
  }



  /**
   * Decodes the provided JSON value as a password quality requirement
   * validation result.
   *
   * @param  controlObject  A JSON object containing an encoded representation
   *                        of the control being decoded.  It must not be
   *                        {@code null}.
   * @param  resultValue    The JSON value to be decoded as a password quality
   *                        requirement validation result.  It must not be
   *                        {@code null}.
   * @param  strict         Indicates whether to use strict mode when decoding
   *                        the provided JSON object.  If this is {@code true},
   *                        then this method will throw an exception if the
   *                        provided JSON value is an object that contains any
   *                        unrecognized fields.  If this is {@code false}, then
   *                        unrecognized fields will be ignored.
   *
   * @return  The password quality requirement validation result that was
   *          decoded.
   *
   * @throws  LDAPException  If the provided JSON value cannot be decoded as a
   *                         password quality requirement validation result.
   */
  @NotNull()
  private static PasswordQualityRequirementValidationResult
               decodeValidationResultJSON(
                    @NotNull final JSONObject controlObject,
                    @NotNull final JSONValue resultValue,
                    final boolean strict)
          throws LDAPException
  {
    if (! (resultValue instanceof JSONObject))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_VALIDATION_RESPONSE_JSON_RESULT_NOT_OBJECT.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_VALIDATION_DETAILS));
    }

    final JSONObject resultObject = (JSONObject) resultValue;

    final JSONObject requirementObject =
         resultObject.getFieldAsObject(JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT);
    if (requirementObject == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_VALIDATION_RESPONSE_JSON_RESULT_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_VALIDATION_DETAILS,
                JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT));
    }

    final String requirementDescription =
         requirementObject.getFieldAsString(JSON_FIELD_DESCRIPTION);
    if (requirementDescription == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_VALIDATION_RESPONSE_JSON_REQUIREMENT_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_VALIDATION_DETAILS,
                JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT,
                JSON_FIELD_DESCRIPTION));
    }

    final String clientSideValidationType = requirementObject.getFieldAsString(
         JSON_FIELD_CLIENT_SIDE_VALIDATION_TYPE);

    final Map<String,String> clientSideValidationProperties =
         new LinkedHashMap<>();
    final List<JSONValue> clientSideValidationPropertyValues =
         requirementObject.getFieldAsArray(
              JSON_FIELD_CLIENT_SIDE_VALIDATION_PROPERTIES);
    if (clientSideValidationPropertyValues != null)
    {
      for (final JSONValue v : clientSideValidationPropertyValues)
      {
        if (! (v instanceof JSONObject))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_PW_VALIDATION_RESPONSE_JSON_REQUIREMENT_PROP_NOT_OBJECT.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_VALIDATION_DETAILS,
                JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT,
                JSON_FIELD_CLIENT_SIDE_VALIDATION_PROPERTIES));
        }

        final JSONObject propObject = (JSONObject) v;
        final String name =
             propObject.getFieldAsString(JSON_FIELD_PROPERTY_NAME);
        if (name == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_PW_VALIDATION_RESPONSE_JSON_REQUIREMENT_PROP_MISSING_FIELD.
                    get(controlObject.toSingleLineString(),
                         JSON_FIELD_VALIDATION_DETAILS,
                         JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT,
                         JSON_FIELD_CLIENT_SIDE_VALIDATION_PROPERTIES,
                         JSON_FIELD_PROPERTY_NAME));
        }

        final String value =
             propObject.getFieldAsString(JSON_FIELD_PROPERTY_VALUE);
        if (value == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_PW_VALIDATION_RESPONSE_JSON_REQUIREMENT_PROP_MISSING_FIELD.
                    get(controlObject.toSingleLineString(),
                         JSON_FIELD_VALIDATION_DETAILS,
                         JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT,
                         JSON_FIELD_CLIENT_SIDE_VALIDATION_PROPERTIES,
                         JSON_FIELD_PROPERTY_VALUE));
        }

        if (strict)
        {
          final List<String> unrecognizedFields =
               JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                    propObject, JSON_FIELD_PROPERTY_NAME,
                    JSON_FIELD_PROPERTY_VALUE);
          if (! unrecognizedFields.isEmpty())
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_PW_VALIDATION_RESPONSE_JSON_UNRECOGNIZED_PROP_FIELD.get(
                      controlObject.toSingleLineString(),
                      JSON_FIELD_VALIDATION_DETAILS,
                      JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT,
                      JSON_FIELD_CLIENT_SIDE_VALIDATION_PROPERTIES,
                      unrecognizedFields.get(0)));
          }
        }

        clientSideValidationProperties.put(name, value);
      }
    }


    final Boolean requirementSatisfied =
         resultObject.getFieldAsBoolean(JSON_FIELD_REQUIREMENT_SATISFIED);
    if (requirementSatisfied == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_VALIDATION_RESPONSE_JSON_RESULT_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_VALIDATION_DETAILS,
                JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT,
                JSON_FIELD_REQUIREMENT_SATISFIED));
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                resultObject, JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT,
                JSON_FIELD_REQUIREMENT_SATISFIED,
                JSON_FIELD_ADDITIONAL_INFORMATION);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PW_VALIDATION_RESPONSE_JSON_RESULT_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  JSON_FIELD_VALIDATION_DETAILS,
                  JSON_FIELD_PASSWORD_QUALITY_REQUIREMENT,
                  unrecognizedFields.get(0)));
      }
    }


    final String additionalInformation =
         resultObject.getFieldAsString(JSON_FIELD_ADDITIONAL_INFORMATION);

    final PasswordQualityRequirement requirement =
         new PasswordQualityRequirement(requirementDescription,
              clientSideValidationType, clientSideValidationProperties);
    return new PasswordQualityRequirementValidationResult(requirement,
         requirementSatisfied, additionalInformation);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PasswordValidationDetailsResponseControl(responseType='");
    buffer.append(responseType.name());
    buffer.append('\'');

    if (responseType ==
        PasswordValidationDetailsResponseType.VALIDATION_DETAILS)
    {
      buffer.append(", validationDetails={");

      final Iterator<PasswordQualityRequirementValidationResult> iterator =
           validationResults.iterator();
      while (iterator.hasNext())
      {
        iterator.next().toString(buffer);
        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
    }

    buffer.append(", missingCurrentPassword=");
    buffer.append(missingCurrentPassword);
    buffer.append(", mustChangePassword=");
    buffer.append(mustChangePassword);

    if (secondsUntilExpiration != null)
    {
      buffer.append(", secondsUntilExpiration=");
      buffer.append(secondsUntilExpiration);
    }

    buffer.append("})");
  }
}
