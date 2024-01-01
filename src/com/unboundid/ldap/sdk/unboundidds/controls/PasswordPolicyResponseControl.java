/*
 * Copyright 2007-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2024 Ping Identity Corporation
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
 * Copyright (C) 2007-2024 Ping Identity Corporation
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of the password policy response control
 * as described in draft-behera-ldap-password-policy.  It may be used to provide
 * information related to a user's password policy.  It may include at most one
 * warning from the set of {@link PasswordPolicyWarningType} values and at most
 * one error from the set of {@link PasswordPolicyErrorType} values.  See the
 * documentation for those classes for more information on the information that
 * may be included.  See the {@link PasswordPolicyRequestControl} documentation
 * for an example that demonstrates the use of the password policy request and
 * response controls.
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
 * The control has an OID of 1.3.6.1.4.1.42.2.27.8.5.1 and a criticality of
 * false.  It must have a value with the following encoding:
 * <PRE>
 *   PasswordPolicyResponseValue ::= SEQUENCE {
 *      warning [0] CHOICE {
 *         timeBeforeExpiration [0] INTEGER (0 .. maxInt),
 *         graceAuthNsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL,
 *      error   [1] ENUMERATED {
 *         passwordExpired             (0),
 *         accountLocked               (1),
 *         changeAfterReset            (2),
 *         passwordModNotAllowed       (3),
 *         mustSupplyOldPassword       (4),
 *         insufficientPasswordQuality (5),
 *         passwordTooShort            (6),
 *         passwordTooYoung            (7),
 *         passwordInHistory           (8) } OPTIONAL }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordPolicyResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.42.2.27.8.5.1) for the password policy response
   * control.
   */
  @NotNull public static final String PASSWORD_POLICY_RESPONSE_OID =
       "1.3.6.1.4.1.42.2.27.8.5.1";



  /**
   * The BER type for the password policy warning element.
   */
  private static final byte TYPE_WARNING = (byte) 0xA0;



  /**
   * The BER type for the password policy error element.
   */
  private static final byte TYPE_ERROR = (byte) 0x81;



  /**
   * The BER type for the "time before expiration" warning element.
   */
  private static final byte TYPE_TIME_BEFORE_EXPIRATION = (byte) 0x80;



  /**
   * The BER type for the "grace logins remaining" warning element.
   */
  private static final byte TYPE_GRACE_LOGINS_REMAINING = (byte) 0x81;



  /**
   * The name of the field used to hold the error type in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_ERROR_TYPE = "error-type";



  /**
   * The name of the field used to hold the grace logins remaining in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_GRACE_LOGINS_REMAINING =
       "grace-logins-remaining";



  /**
   * The name of the field used to hold the seconds until expiration in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SECONDS_UNTIL_EXPIRATION =
       "seconds-until-expiration";



  /**
   * The name of the field used to hold the warning in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_WARNING = "warning";



  /**
   * The value to use for the account-locked error type in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_ERROR_TYPE_ACCOUNT_LOCKED =
       "account-locked";



  /**
   * The value to use for the change-after-reset error type in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_ERROR_TYPE_CHANGE_AFTER_RESET =
       "change-after-reset";



  /**
   * The value to use for the insufficient-password-quality error type in the
   * JSON representation of this control.
   */
  @NotNull private static final String
       JSON_ERROR_TYPE_INSUFFICIENT_PASSWORD_QUALITY =
            "insufficient-password-quality";



  /**
   * The value to use for the must-supply-old-password error type in the JSON
   * representation of this control.
   */
  @NotNull private static final String
       JSON_ERROR_TYPE_MUST_SUPPLY_OLD_PASSWORD = "must-supply-old-password";



  /**
   * The value to use for the password-expired error type in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_ERROR_TYPE_PASSWORD_EXPIRED =
       "password-expired";



  /**
   * The value to use for the password-in-history error type in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_ERROR_TYPE_PASSWORD_IN_HISTORY =
       "password-in-history";



  /**
   * The value to use for the password-too-short error type in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_ERROR_TYPE_PASSWORD_TOO_SHORT =
       "password-too-short";



  /**
   * The value to use for the password-too-young error type in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_ERROR_TYPE_PASSWORD_TOO_YOUNG =
       "password-too-young";



  /**
   * The value to use for the password-mod-not-allowed error type in the JSON
   * representation of this control.
   */
  @NotNull private static final String
       JSON_ERROR_TYPE_PASSWORD_MOD_NOT_ALLOWED = "password-mod-not-allowed";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1835830253434331833L;



  // The password policy warning value, if applicable.
  private final int warningValue;

  // The password policy error type, if applicable.
  @Nullable private final PasswordPolicyErrorType errorType;

  // The password policy warning type, if applicable.
  @Nullable private final PasswordPolicyWarningType warningType;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  PasswordPolicyResponseControl()
  {
    warningType  = null;
    errorType    = null;
    warningValue = -1;
  }



  /**
   * Creates a new password policy response control with the provided
   * information.  It will not be critical.
   *
   * @param  warningType   The password policy warning type for this response
   *                       control, or {@code null} if there should be no
   *                       warning type.
   * @param  warningValue  The value for the password policy warning type, or -1
   *                       if there is no warning type.
   * @param  errorType     The password policy error type for this response
   *                       control, or {@code null} if there should be no error
   *                       type.
   */
  public PasswordPolicyResponseControl(
              @Nullable final PasswordPolicyWarningType warningType,
              final int warningValue,
              @Nullable final PasswordPolicyErrorType errorType)
  {
    this(warningType, warningValue, errorType, false);
  }



  /**
   * Creates a new password policy response control with the provided
   * information.
   *
   * @param  warningType   The password policy warning type for this response
   *                       control, or {@code null} if there should be no
   *                       warning type.
   * @param  warningValue  The value for the password policy warning type, or -1
   *                       if there is no warning type.
   * @param  errorType     The password policy error type for this response
   *                       control, or {@code null} if there should be no error
   *                       type.
   * @param  isCritical    Indicates whether this control should be marked
   *                       critical.  Response controls should generally not be
   *                       critical.
   */
  public PasswordPolicyResponseControl(
              @Nullable final PasswordPolicyWarningType warningType,
              final int warningValue,
              @Nullable final PasswordPolicyErrorType errorType,
              final boolean isCritical)
  {
    super(PASSWORD_POLICY_RESPONSE_OID, isCritical,
          encodeValue(warningType, warningValue, errorType));

    this.warningType = warningType;
    this.errorType   = errorType;

    if (warningType == null)
    {
      this.warningValue = -1;
    }
    else
    {
      this.warningValue = warningValue;
    }
  }



  /**
   * Creates a new password policy response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         password policy response control.
   */
  public PasswordPolicyResponseControl(@NotNull final String oid,
                                       final boolean isCritical,
                                       @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_RESPONSE_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_RESPONSE_VALUE_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if (valueElements.length > 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_RESPONSE_INVALID_ELEMENT_COUNT.get(
                                   valueElements.length));
    }

    int                       wv = -1;
    PasswordPolicyErrorType   et = null;
    PasswordPolicyWarningType wt = null;
    for (final ASN1Element e : valueElements)
    {
      switch (e.getType())
      {
        case TYPE_WARNING:
          if (wt == null)
          {
            try
            {
              final ASN1Element warningElement =
                   ASN1Element.decode(e.getValue());
              wv = ASN1Integer.decodeAsInteger(warningElement).intValue();
              switch (warningElement.getType())
              {
                case TYPE_TIME_BEFORE_EXPIRATION:
                  wt = PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION;
                  break;

                case TYPE_GRACE_LOGINS_REMAINING:
                  wt = PasswordPolicyWarningType.GRACE_LOGINS_REMAINING;
                  break;

                default:
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_PWP_RESPONSE_INVALID_WARNING_TYPE.get(
                            StaticUtils.toHex(warningElement.getType())));
              }
            }
            catch (final ASN1Exception ae)
            {
              Debug.debugException(ae);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_PWP_RESPONSE_CANNOT_DECODE_WARNING.get(ae), ae);
            }
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                                    ERR_PWP_RESPONSE_MULTIPLE_WARNING.get());
          }
          break;

        case TYPE_ERROR:
          if (et == null)
          {
            try
            {
              final ASN1Enumerated errorElement =
                   ASN1Enumerated.decodeAsEnumerated(e);
              et = PasswordPolicyErrorType.valueOf(errorElement.intValue());
              if (et == null)
              {
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_PWP_RESPONSE_INVALID_ERROR_TYPE.get(
                            errorElement.intValue()));
              }
            }
            catch (final ASN1Exception ae)
            {
              Debug.debugException(ae);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_PWP_RESPONSE_CANNOT_DECODE_ERROR.get(ae), ae);
            }
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_PWP_RESPONSE_MULTIPLE_ERROR.get());
          }
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_PWP_RESPONSE_INVALID_TYPE.get(
                    StaticUtils.toHex(e.getType())));
      }
    }

    warningType  = wt;
    warningValue = wv;
    errorType    = et;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public PasswordPolicyResponseControl
              decodeControl(@NotNull final String oid, final boolean isCritical,
                            @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new PasswordPolicyResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts a password policy response control from the provided result.
   *
   * @param  result  The result from which to retrieve the password policy
   *                 response control.
   *
   * @return  The password policy response control contained in the provided
   *          result, or {@code null} if the result did not contain a password
   *          policy response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the password policy response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static PasswordPolicyResponseControl get(
                     @NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(PASSWORD_POLICY_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof PasswordPolicyResponseControl)
    {
      return (PasswordPolicyResponseControl) c;
    }
    else
    {
      return new PasswordPolicyResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Encodes the provided information as appropriate for use as the value of a
   * password policy response control.
   *
   * @param  warningType   The warning type to use for the warning element, or
   *                       {@code null} if there is not to be a warning element.
   * @param  warningValue  The value to use for the warning element.
   * @param  errorType     The error type to use for the error element, or
   *                       {@code null} if there is not to be an error element.
   *
   * @return  The ASN.1 octet string containing the encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @Nullable final PasswordPolicyWarningType warningType,
               final int warningValue,
               @Nullable final PasswordPolicyErrorType errorType)
  {
    final ArrayList<ASN1Element> valueElements = new ArrayList<>(2);

    if (warningType != null)
    {
      switch (warningType)
      {
        case TIME_BEFORE_EXPIRATION:
          valueElements.add(new ASN1Element(TYPE_WARNING,
               new ASN1Integer(TYPE_TIME_BEFORE_EXPIRATION,
                               warningValue).encode()));
          break;

        case GRACE_LOGINS_REMAINING:
          valueElements.add(new ASN1Element(TYPE_WARNING,
               new ASN1Integer(TYPE_GRACE_LOGINS_REMAINING,
                               warningValue).encode()));
          break;
      }
    }

    if (errorType != null)
    {
      valueElements.add(new ASN1Enumerated(TYPE_ERROR, errorType.intValue()));
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }



  /**
   * Retrieves the warning type for this password policy response control, if
   * available.
   *
   * @return  The warning type for this password policy response control, or
   *          {@code null} if there is no warning type.
   */
  @Nullable()
  public PasswordPolicyWarningType getWarningType()
  {
    return warningType;
  }



  /**
   * Retrieves the warning value for this password policy response control, if
   * available.
   *
   * @return  The warning value for this password policy response control, or -1
   *          if there is no warning type.
   */
  public int getWarningValue()
  {
    return warningValue;
  }



  /**
   * Retrieves the error type for this password policy response control, if
   * available.
   *
   * @return  The error type for this password policy response control, or
   *          {@code null} if there is no error type.
   */
  @Nullable()
  public PasswordPolicyErrorType getErrorType()
  {
    return errorType;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PW_POLICY_RESPONSE.get();
  }



  /**
   * Retrieves a representation of this password policy response control as a
   * JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the password policy response control,
   *     the OID is "1.3.6.1.4.1.42.2.27.8.5.1".
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
   *     base64-encoded representation of the raw value for this password policy
   *     response control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this password policy
   *     response control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code warning} -- An optional JSON object field whose value
   *         represents a warning about the user's password policy state.  If
   *         present, the JSON object must contain exactly one of the following
   *         fields:
   *         <UL>
   *           <LI>
   *             {@code seconds-until-expiration} -- An integer field whose
   *             value is the number of seconds until the user's password
   *             expires.
   *           </LI>
   *           <LI>
   *             {@code grace-logins-remaining} -- An integer field whose value
   *             value is the number of grace login attempts that the user has
   *             left.
   *           </LI>
   *         </UL>
   *       </LI>
   *       <LI>
   *         {@code error-type} -- An optional string field whose value
   *         represents a password policy error condition that applies to the
   *         associated operation.  If present, its value will be one of the
   *         following:
   *         <UL>
   *           <LI>{@code password-expired}</LI>
   *           <LI>{@code account-locked}</LI>
   *           <LI>{@code change-after-reset}</LI>
   *           <LI>{@code password-mod-not-allowed}</LI>
   *           <LI>{@code must-supply-old-password}</LI>
   *           <LI>{@code insufficient-password-quality}</LI>
   *           <LI>{@code password-too-short}</LI>
   *           <LI>{@code password-too-young}</LI>
   *           <LI>{@code password-in-history}</LI>
   *         </UL>
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

    if (warningType != null)
    {
      switch (warningType)
      {
        case TIME_BEFORE_EXPIRATION:
          valueFields.put(JSON_FIELD_WARNING, new JSONObject(
               new JSONField(JSON_FIELD_SECONDS_UNTIL_EXPIRATION,
                    warningValue)));
          break;
        case GRACE_LOGINS_REMAINING:
          valueFields.put(JSON_FIELD_WARNING, new JSONObject(
               new JSONField(JSON_FIELD_GRACE_LOGINS_REMAINING, warningValue)));
          break;
      }
    }

    if (errorType != null)
    {
      switch (errorType)
      {
        case PASSWORD_EXPIRED:
          valueFields.put(JSON_FIELD_ERROR_TYPE,
               new JSONString(JSON_ERROR_TYPE_PASSWORD_EXPIRED));
          break;
        case ACCOUNT_LOCKED:
          valueFields.put(JSON_FIELD_ERROR_TYPE,
               new JSONString(JSON_ERROR_TYPE_ACCOUNT_LOCKED));
          break;
        case CHANGE_AFTER_RESET:
          valueFields.put(JSON_FIELD_ERROR_TYPE,
               new JSONString(JSON_ERROR_TYPE_CHANGE_AFTER_RESET));
          break;
        case PASSWORD_MOD_NOT_ALLOWED:
          valueFields.put(JSON_FIELD_ERROR_TYPE,
               new JSONString(JSON_ERROR_TYPE_PASSWORD_MOD_NOT_ALLOWED));
          break;
        case MUST_SUPPLY_OLD_PASSWORD:
          valueFields.put(JSON_FIELD_ERROR_TYPE,
               new JSONString(JSON_ERROR_TYPE_MUST_SUPPLY_OLD_PASSWORD));
          break;
        case INSUFFICIENT_PASSWORD_QUALITY:
          valueFields.put(JSON_FIELD_ERROR_TYPE,
               new JSONString(JSON_ERROR_TYPE_INSUFFICIENT_PASSWORD_QUALITY));
          break;
        case PASSWORD_TOO_SHORT:
          valueFields.put(JSON_FIELD_ERROR_TYPE,
               new JSONString(JSON_ERROR_TYPE_PASSWORD_TOO_SHORT));
          break;
        case PASSWORD_TOO_YOUNG:
          valueFields.put(JSON_FIELD_ERROR_TYPE,
               new JSONString(JSON_ERROR_TYPE_PASSWORD_TOO_YOUNG));
          break;
        case PASSWORD_IN_HISTORY:
          valueFields.put(JSON_FIELD_ERROR_TYPE,
               new JSONString(JSON_ERROR_TYPE_PASSWORD_IN_HISTORY));
          break;
      }
    }

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              PASSWORD_POLICY_RESPONSE_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_PW_POLICY_RESPONSE.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(valueFields)));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * password policy response control.
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
   * @return  The password policy response control that was decoded from the
   *          provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid password policy response control.
   */
  @NotNull()
  public static PasswordPolicyResponseControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new PasswordPolicyResponseControl(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue);
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final PasswordPolicyWarningType warningType;
    final int warningValue;
    final JSONObject warningObject =
         valueObject.getFieldAsObject(JSON_FIELD_WARNING);
    if (warningObject == null)
    {
      warningType = null;
      warningValue = -1;
    }
    else
    {
      final Integer secondsUntilExpiration =
           warningObject.getFieldAsInteger(JSON_FIELD_SECONDS_UNTIL_EXPIRATION);
      final Integer graceLoginsRemaining =
           warningObject.getFieldAsInteger(JSON_FIELD_GRACE_LOGINS_REMAINING);
      if (secondsUntilExpiration == null)
      {
        if (graceLoginsRemaining == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_PWP_RESPONSE_JSON_NO_RECOGNIZED_WARNING_TYPE.get(
                    controlObject.toSingleLineString(), JSON_FIELD_WARNING));
        }
        else
        {
          warningType = PasswordPolicyWarningType.GRACE_LOGINS_REMAINING;
          warningValue = graceLoginsRemaining;
        }
      }
      else if (graceLoginsRemaining == null)
      {
        warningType = PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION;
        warningValue = secondsUntilExpiration;
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PWP_RESPONSE_JSON_MULTIPLE_WARNING_TYPES.get(
                  controlObject.toSingleLineString(),
                  JSON_FIELD_WARNING));
      }

      if (strict)
      {
        final List<String> unrecognizedFields =
             JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                  warningObject, JSON_FIELD_SECONDS_UNTIL_EXPIRATION,
                  JSON_FIELD_GRACE_LOGINS_REMAINING);
        if (! unrecognizedFields.isEmpty())
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_PWP_RESPONSE_JSON_UNRECOGNIZED_WARNING_FIELD.get(
                    controlObject.toSingleLineString(), JSON_FIELD_WARNING,
                    unrecognizedFields.get(0)));
        }
      }
    }


    final PasswordPolicyErrorType errorType;
    final String errorTypeString =
         valueObject.getFieldAsString(JSON_FIELD_ERROR_TYPE);
    if (errorTypeString == null)
    {
      errorType = null;
    }
    else
    {
      switch (errorTypeString)
      {
        case JSON_ERROR_TYPE_PASSWORD_EXPIRED:
          errorType = PasswordPolicyErrorType.PASSWORD_EXPIRED;
          break;
        case JSON_ERROR_TYPE_ACCOUNT_LOCKED:
          errorType = PasswordPolicyErrorType.ACCOUNT_LOCKED;
          break;
        case JSON_ERROR_TYPE_CHANGE_AFTER_RESET:
          errorType = PasswordPolicyErrorType.CHANGE_AFTER_RESET;
          break;
        case JSON_ERROR_TYPE_PASSWORD_MOD_NOT_ALLOWED:
          errorType = PasswordPolicyErrorType.PASSWORD_MOD_NOT_ALLOWED;
          break;
        case JSON_ERROR_TYPE_MUST_SUPPLY_OLD_PASSWORD:
          errorType = PasswordPolicyErrorType.MUST_SUPPLY_OLD_PASSWORD;
          break;
        case JSON_ERROR_TYPE_INSUFFICIENT_PASSWORD_QUALITY:
          errorType = PasswordPolicyErrorType.INSUFFICIENT_PASSWORD_QUALITY;
          break;
        case JSON_ERROR_TYPE_PASSWORD_TOO_SHORT:
          errorType = PasswordPolicyErrorType.PASSWORD_TOO_SHORT;
          break;
        case JSON_ERROR_TYPE_PASSWORD_TOO_YOUNG:
          errorType = PasswordPolicyErrorType.PASSWORD_TOO_YOUNG;
          break;
        case JSON_ERROR_TYPE_PASSWORD_IN_HISTORY:
          errorType = PasswordPolicyErrorType.PASSWORD_IN_HISTORY;
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_PWP_RESPONSE_JSON_UNRECOGNIZED_ERROR_TYPE.get(
                    controlObject.toSingleLineString(), JSON_FIELD_ERROR_TYPE,
                    errorTypeString));
      }
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_WARNING, JSON_FIELD_ERROR_TYPE);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PWP_RESPONSE_JSON_UNRECOGNIZED_VALUE_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new PasswordPolicyResponseControl(warningType, warningValue,
         errorType, jsonControl.getCriticality());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {

    buffer.append("PasswordPolicyResponseControl(");

    boolean elementAdded = false;
    if (warningType != null)
    {
      buffer.append("warningType='");
      buffer.append(warningType.getName());
      buffer.append("', warningValue=");
      buffer.append(warningValue);
      elementAdded = true;
    }

    if (errorType != null)
    {
      if (elementAdded)
      {
        buffer.append(", ");
      }

      buffer.append("errorType='");
      buffer.append(errorType.getName());
      buffer.append('\'');
      elementAdded = true;
    }

    if (elementAdded)
    {
      buffer.append(", ");
    }

    buffer.append("isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
