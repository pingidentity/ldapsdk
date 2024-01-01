/*
 * Copyright 2017-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2024 Ping Identity Corporation
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
 * Copyright (C) 2017-2024 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a request control that can be
 * included in an add request, modify request, or password modify extended
 * request to control the way the server should behave when performing a
 * password change.  The requester must have the password-reset privilege.
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
 * This request control has an OID of 1.3.6.1.4.1.30221.2.5.51.  The criticality
 * may be either true or false.  It must have a value, and the value should have
 * the following encoding:
 * <PRE>
 *   PasswordUpdateBehaviorRequest ::= SEQUENCE {
 *        isSelfChange                        [0] BOOLEAN OPTIONAL,
 *        allowPreEncodedPassword             [1] BOOLEAN OPTIONAL,
 *        skipPasswordValidation              [2] BOOLEAN OPTIONAL,
 *        ignorePasswordHistory               [3] BOOLEAN OPTIONAL,
 *        ignoreMinimumPasswordAge            [4] BOOLEAN OPTIONAL,
 *        passwordStorageScheme               [5] OCTET STRING OPTIONAL,
 *        mustChangePassword                  [6] BOOLEAN OPTIONAL,
 *        ... }
 * </PRE>
 *
 * @see  PasswordUpdateBehaviorRequestControlProperties
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordUpdateBehaviorRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.51) for the password update behavior request
   * control.
   */
  @NotNull public static final String PASSWORD_UPDATE_BEHAVIOR_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.51";



  /**
   * The BER type to use for the {@code isSelfChange} element in the encoded
   * request.
   */
  private static final byte TYPE_IS_SELF_CHANGE = (byte) 0x80;



  /**
   * The BER type to use for the {@code allowPreEncodedPassword} element in the
   * encoded request.
   */
  private static final byte TYPE_ALLOW_PRE_ENCODED_PASSWORD = (byte) 0x81;



  /**
   * The BER type to use for the {@code skipPasswordValidation} element in the
   * encoded request.
   */
  private static final byte TYPE_SKIP_PASSWORD_VALIDATION = (byte) 0x82;



  /**
   * The BER type to use for the {@code ignorePasswordHistory} element in the
   * encoded request.
   */
  private static final byte TYPE_IGNORE_PASSWORD_HISTORY = (byte) 0x83;



  /**
   * The BER type to use for the {@code ignoreMinimumPasswordAge} element in the
   * encoded request.
   */
  private static final byte TYPE_IGNORE_MINIMUM_PASSWORD_AGE = (byte) 0x84;



  /**
   * The BER type to use for the {@code passwordStorageScheme} element in the
   * encoded request.
   */
  private static final byte TYPE_PASSWORD_STORAGE_SCHEME = (byte) 0x85;



  /**
   * The BER type to use for the {@code mustChangePassword} element in the
   * encoded request.
   */
  private static final byte TYPE_MUST_CHANGE_PASSWORD = (byte) 0x86;



  /**
   * The name of the field used to hold the allow-pre-encoded-password value in
   * the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_ALLOW_PRE_ENCODED_PASSWORD =
       "allow-pre-encoded-password";



  /**
   * The name of the field used to hold the ignore-minimum-password-age value in
   * the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_IGNORE_MINIMUM_PASSWORD_AGE =
       "ignore-minimum-password-age";



  /**
   * The name of the field used to hold the ignore-password-history value in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_IGNORE_PASSWORD_HISTORY =
       "ignore-password-history";



  /**
   * The name of the field used to hold the is-self-change value in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_IS_SELF_CHANGE =
       "is-self-change";



  /**
   * The name of the field used to hold the must-change-password value in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_MUST_CHANGE_PASSWORD =
       "must-change-password";



  /**
   * The name of the field used to hold the password-storage-scheme value in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_PASSWORD_STORAGE_SCHEME =
       "password-storage-scheme";



  /**
   * The name of the field used to hold the skip-password-validation value in
   * the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SKIP_PASSWORD_VALIDATION =
       "skip-password-validation";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1915608505128236450L;



  // Indicates whether the requester should be allowed to provide a pre-encoded
  // password.
  @Nullable private final Boolean allowPreEncodedPassword;

  // Indicates whether to ignore any minimum password age configured in the
  // password policy.
  @Nullable private final Boolean ignoreMinimumPasswordAge;

  // Indicates whether to skip the process of checking whether the provided
  // password matches the new current password or is in the password history.
  @Nullable private final Boolean ignorePasswordHistory;

  // Indicates whether to treat the password change as a self change.
  @Nullable private final Boolean isSelfChange;

  // Indicates whether to update the user's account to indicate that they must
  // change their password the next time they authenticate.
  @Nullable private final Boolean mustChangePassword;

  // Indicates whether to skip password validation for the new password.
  @Nullable private final Boolean skipPasswordValidation;

  // Specifies the password storage scheme to use for the new password.
  @Nullable private final String passwordStorageScheme;



  /**
   * Creates a new password update behavior request control with the provided
   * information.
   *
   * @param  properties  The set of properties to use for the request control.
   *                     It must not be {@code null}.
   * @param  isCritical  Indicates whether the control should be considered
   *                     critical.
   */
  public PasswordUpdateBehaviorRequestControl(
       @NotNull final PasswordUpdateBehaviorRequestControlProperties properties,
       final boolean isCritical)
  {
    super(PASSWORD_UPDATE_BEHAVIOR_REQUEST_OID, isCritical,
         encodeValue(properties));

    isSelfChange = properties.getIsSelfChange();
    allowPreEncodedPassword = properties.getAllowPreEncodedPassword();
    skipPasswordValidation = properties.getSkipPasswordValidation();
    ignorePasswordHistory = properties.getIgnorePasswordHistory();
    ignoreMinimumPasswordAge = properties.getIgnoreMinimumPasswordAge();
    passwordStorageScheme = properties.getPasswordStorageScheme();
    mustChangePassword = properties.getMustChangePassword();
  }



  /**
   * Creates a new password update behavior request control that is decoded from
   * the provided generic control.
   *
   * @param  control  The control to be decoded as a password update behavior
   *                  request control.  It must not be {@code null}.
   *
   * @throws  LDAPException  If the provided control cannot be parsed as a
   *                         password update behavior request control.
   */
  public PasswordUpdateBehaviorRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_UPDATE_BEHAVIOR_REQ_DECODE_NO_VALUE.get());
    }

    try
    {
      Boolean allowPreEncoded = null;
      Boolean ignoreAge = null;
      Boolean ignoreHistory = null;
      Boolean mustChange = null;
      Boolean selfChange = null;
      Boolean skipValidation = null;
      String scheme = null;
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(value.getValue()).elements())
      {
        switch (e.getType())
        {
          case TYPE_IS_SELF_CHANGE:
            selfChange = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_ALLOW_PRE_ENCODED_PASSWORD:
            allowPreEncoded = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_SKIP_PASSWORD_VALIDATION:
            skipValidation = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_IGNORE_PASSWORD_HISTORY:
            ignoreHistory = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_IGNORE_MINIMUM_PASSWORD_AGE:
            ignoreAge = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_PASSWORD_STORAGE_SCHEME:
            scheme = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_MUST_CHANGE_PASSWORD:
            mustChange = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_PW_UPDATE_BEHAVIOR_REQ_DECODE_UNRECOGNIZED_ELEMENT_TYPE.
                      get(StaticUtils.toHex(e.getType())));
        }
      }

      isSelfChange = selfChange;
      allowPreEncodedPassword = allowPreEncoded;
      skipPasswordValidation = skipValidation;
      ignorePasswordHistory = ignoreHistory;
      ignoreMinimumPasswordAge = ignoreAge;
      passwordStorageScheme = scheme;
      mustChangePassword = mustChange;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_UPDATE_BEHAVIOR_REQ_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided properties into a form that can be used as the value
   * for this control.
   *
   * @param  properties  The properties to be encoded.
   *
   * @return  An ASN.1 octet string that can be used as the request control
   *          value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
       @NotNull final PasswordUpdateBehaviorRequestControlProperties properties)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(6);

    if (properties.getIsSelfChange() != null)
    {
      elements.add(new ASN1Boolean(TYPE_IS_SELF_CHANGE,
           properties.getIsSelfChange()));
    }

    if (properties.getAllowPreEncodedPassword() != null)
    {
      elements.add(new ASN1Boolean(TYPE_ALLOW_PRE_ENCODED_PASSWORD,
           properties.getAllowPreEncodedPassword()));
    }

    if (properties.getSkipPasswordValidation() != null)
    {
      elements.add(new ASN1Boolean(TYPE_SKIP_PASSWORD_VALIDATION,
           properties.getSkipPasswordValidation()));
    }

    if (properties.getIgnorePasswordHistory() != null)
    {
      elements.add(new ASN1Boolean(TYPE_IGNORE_PASSWORD_HISTORY,
           properties.getIgnorePasswordHistory()));
    }

    if (properties.getIgnoreMinimumPasswordAge() != null)
    {
      elements.add(new ASN1Boolean(TYPE_IGNORE_MINIMUM_PASSWORD_AGE,
           properties.getIgnoreMinimumPasswordAge()));
    }

    if (properties.getPasswordStorageScheme() != null)
    {
      elements.add(new ASN1OctetString(TYPE_PASSWORD_STORAGE_SCHEME,
           properties.getPasswordStorageScheme()));
    }

    if (properties.getMustChangePassword() != null)
    {
      elements.add(new ASN1Boolean(TYPE_MUST_CHANGE_PASSWORD,
           properties.getMustChangePassword()));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Indicates whether this control should override the server's automatic
   * classification of the password update as a self change or an administrative
   * reset, and if so, what the overridden value should be.
   *
   * @return  {@code Boolean.TRUE} if the server should treat the password
   *          update as a self change, {@code Boolean.FALSE} if the server
   *          should treat the password update as an administrative reset, or
   *          {@code null} if the server should automatically determine whether
   *          the password update is a self change or an administrative reset.
   */
  @Nullable()
  public Boolean getIsSelfChange()
  {
    return isSelfChange;
  }



  /**
   * Indicates whether this control should override the value of the
   * {@code allow-pre-encoded-passwords} configuration property for the target
   * user's password policy, and if so, what the overridden value should be.
   *
   * @return  {@code Boolean.TRUE} if the server should accept a pre-encoded
   *          password in the password update even if the server's password
   *          policy configuration would normally not permit this,
   *          {@code Boolean.FALSE} if the server should reject a pre-encoded
   *          password in the password update even if the server's password
   *          policy configuration would normally accept it, or {@code null} if
   *          the password policy configuration should be used to determine
   *          whether to accept pre-encoded passwords.
   */
  @Nullable()
  public Boolean getAllowPreEncodedPassword()
  {
    return allowPreEncodedPassword;
  }



  /**
   * Indicates whether this control should override the server's normal behavior
   * with regard to invoking password validators for any new passwords included
   * in the password update, and if so, what the overridden behavior should be.
   *
   * @return  {@code Boolean.TRUE} if the server should skip invoking the
   *          password validators configured in the target user's password
   *          policy validators for any new passwords included in the password
   *          update even if the server would normally perform password
   *          validation, {@code Boolean.FALSE} if the server should invoke the
   *          password validators even if it would normally skip them, or
   *          {@code null} if the password policy configuration should be used
   *          to determine whether to skip password validation.
   */
  @Nullable()
  public Boolean getSkipPasswordValidation()
  {
    return skipPasswordValidation;
  }



  /**
   * Indicates whether this control should override the server's normal behavior
   * with regard to checking the password history for any new passwords included
   * in the password update, and if so, what the overridden behavior should be.
   *
   * @return  {@code Boolean.TRUE} if the server should not check to see whether
   *          any new password matches the current password or is in the user's
   *          password history even if it would normally perform that check,
   *          {@code Boolean.FALSE} if the server should check to see whether
   *          any new password matches the current or previous password even if
   *          it would normally not perform such a check, or {@code null} if the
   *          password policy configuration should be used to determine whether
   *          to ignore the password history.
   */
  @Nullable()
  public Boolean getIgnorePasswordHistory()
  {
    return ignorePasswordHistory;
  }



  /**
   * Indicates whether this control should override the server's normal behavior
   * with regard to checking the minimum password age, and if so, what the
   * overridden behavior should be.
   *
   * @return  {@code Boolean.TRUE} if the server should accept the password
   *          change even if it has been less than the configured minimum
   *          password age since the password was last changed,
   *          {@code Boolean.FALSE} if the server should reject the password
   *          change if it has been less than teh configured minimum password
   *          age, or {@code null} if the password policy configuration should
   *          be used to determine the appropriate behavior.
   */
  @Nullable()
  public Boolean getIgnoreMinimumPasswordAge()
  {
    return ignoreMinimumPasswordAge;
  }



  /**
   * Indicates whether this control should override the server's normal behavior
   * with regard to selecting the password storage scheme to use to encode new
   * password values, and if so, which password storage scheme should be used.
   *
   * @return  The name of the password storage scheme that should be used to
   *          encode any new password values, or {@code null} if the target
   *          user's password policy configuration should determine the
   *          appropriate schemes for encoding new passwords.
   */
  @Nullable()
  public String getPasswordStorageScheme()
  {
    return passwordStorageScheme;
  }



  /**
   * Indicates whether this control should override the server's normal behavior
   * with regard to requiring a password change, and if so, what that behavior
   * should be.
   *
   * @return  {@code Boolean.TRUE} if the user will be required to change their
   *          password before being allowed to perform any other operation,
   *          {@code Boolean.FALSE} if the user will not be required to change
   *          their password before being allowed to perform any other
   *          operation, or {@code null} if the password policy configuration
   *          should be used to control this behavior.
   */
  @Nullable()
  public Boolean getMustChangePassword()
  {
    return mustChangePassword;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_PW_UPDATE_BEHAVIOR_REQ_CONTROL_NAME.get();
  }



  /**
   * Retrieves a representation of this password update behavior request control
   * as a JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the password update behavior request
   *     control, the OID is "1.3.6.1.4.1.30221.2.5.51".
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
   *     base64-encoded representation of the raw value for this password update
   *     behavior request control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this password update
   *     behavior request control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code is-self-change} -- An optional Boolean field that may be
   *         used to explicitly indicate whether the server should treat the
   *         password update as a self change or an administrative reset.
   *       </LI>
   *       <LI>
   *         {@code allow-pre-encoded-password} -- An optional Boolean field
   *         that may be used to explicitly indicate whether the server should
   *         allow the new password to be provided in pre-encoded form.
   *       </LI>
   *       <LI>
   *         {@code skip-password-validation} -- An optional Boolean field that
   *         may be used to explicitly indicate whether the server should skip
   *         the password validation processing that it may otherwise perform
   *         for the new password.
   *       </LI>
   *       <LI>
   *         {@code ignore-password-history} -- An optional Boolean field that
   *         may be used to explicitly indicate whether the server should ignore
   *         the user's password history when determining whether to accept the
   *         new password.
   *       </LI>
   *       <LI>
   *         {@code ignore-minimum-password-age} -- An optional Boolean field
   *         that may be used to explicitly indicate whether the server should
   *         ignore any minimum password age constraints that may otherwise be
   *         in place for the user.
   *       </LI>
   *       <LI>
   *         {@code password-storage-scheme} -- An optional string field whose
   *         value is the name of the password storage scheme that the server
   *         should use when encoding the new password.
   *       </LI>
   *       <LI>
   *         {@code must-change-password} -- An optional Boolean field that may
   *         be used to explicitly indicate whether the server should require
   *         the user to change their password before they will be allowed to
   *         request any other operations.
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

    if (isSelfChange != null)
    {
      valueFields.put(JSON_FIELD_IS_SELF_CHANGE, new JSONBoolean(isSelfChange));
    }

    if (allowPreEncodedPassword != null)
    {
      valueFields.put(JSON_FIELD_ALLOW_PRE_ENCODED_PASSWORD,
           new JSONBoolean(allowPreEncodedPassword));
    }

    if (skipPasswordValidation != null)
    {
      valueFields.put(JSON_FIELD_SKIP_PASSWORD_VALIDATION,
           new JSONBoolean(skipPasswordValidation));
    }

    if (ignorePasswordHistory != null)
    {
      valueFields.put(JSON_FIELD_IGNORE_PASSWORD_HISTORY,
           new JSONBoolean(ignorePasswordHistory));
    }

    if (ignoreMinimumPasswordAge != null)
    {
      valueFields.put(JSON_FIELD_IGNORE_MINIMUM_PASSWORD_AGE,
           new JSONBoolean(ignoreMinimumPasswordAge));
    }

    if (passwordStorageScheme != null)
    {
      valueFields.put(JSON_FIELD_PASSWORD_STORAGE_SCHEME,
           new JSONString(passwordStorageScheme));
    }

    if (mustChangePassword != null)
    {
      valueFields.put(JSON_FIELD_MUST_CHANGE_PASSWORD,
           new JSONBoolean(mustChangePassword));
    }

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              PASSWORD_UPDATE_BEHAVIOR_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_PW_UPDATE_BEHAVIOR_REQ_CONTROL_NAME.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(valueFields)));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * password update behavior control.
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
   * @return  The password update behavior request control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid password update behavior request control.
   */
  @NotNull()
  public static PasswordUpdateBehaviorRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new PasswordUpdateBehaviorRequestControl(new Control(
           jsonControl.getOID(), jsonControl.getCriticality(), rawValue));
    }


    final PasswordUpdateBehaviorRequestControlProperties properties =
         new PasswordUpdateBehaviorRequestControlProperties();
    final JSONObject valueObject = jsonControl.getValueObject();

    final Boolean isSelfChange =
         valueObject.getFieldAsBoolean(JSON_FIELD_IS_SELF_CHANGE);
    if (isSelfChange != null)
    {
      properties.setIsSelfChange(isSelfChange);
    }

    final Boolean allowPreEncodedPassword =
         valueObject.getFieldAsBoolean(JSON_FIELD_ALLOW_PRE_ENCODED_PASSWORD);
    if (allowPreEncodedPassword != null)
    {
      properties.setAllowPreEncodedPassword(allowPreEncodedPassword);
    }

    final Boolean skipPasswordValidation =
         valueObject.getFieldAsBoolean(JSON_FIELD_SKIP_PASSWORD_VALIDATION);
    if (skipPasswordValidation != null)
    {
      properties.setSkipPasswordValidation(skipPasswordValidation);
    }

    final Boolean ignorePasswordHistory =
         valueObject.getFieldAsBoolean(JSON_FIELD_IGNORE_PASSWORD_HISTORY);
    if (ignorePasswordHistory != null)
    {
      properties.setIgnorePasswordHistory(ignorePasswordHistory);
    }

    final Boolean ignoreMinimumPasswordAge =
         valueObject.getFieldAsBoolean(JSON_FIELD_IGNORE_MINIMUM_PASSWORD_AGE);
    if (ignoreMinimumPasswordAge != null)
    {
      properties.setIgnoreMinimumPasswordAge(ignoreMinimumPasswordAge);
    }

    final String passwordStorageScheme =
         valueObject.getFieldAsString(JSON_FIELD_PASSWORD_STORAGE_SCHEME);
    if (passwordStorageScheme != null)
    {
      properties.setPasswordStorageScheme(passwordStorageScheme);
    }

    final Boolean mustChangePassword =
         valueObject.getFieldAsBoolean(JSON_FIELD_MUST_CHANGE_PASSWORD);
    if (mustChangePassword != null)
    {
      properties.setMustChangePassword(mustChangePassword);
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_IS_SELF_CHANGE,
                JSON_FIELD_ALLOW_PRE_ENCODED_PASSWORD,
                JSON_FIELD_SKIP_PASSWORD_VALIDATION,
                JSON_FIELD_IGNORE_PASSWORD_HISTORY,
                JSON_FIELD_IGNORE_MINIMUM_PASSWORD_AGE,
                JSON_FIELD_PASSWORD_STORAGE_SCHEME,
                JSON_FIELD_MUST_CHANGE_PASSWORD);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PW_UPDATE_BEHAVIOR_REQ_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new PasswordUpdateBehaviorRequestControl(properties,
         jsonControl.getCriticality());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PasswordUpdateBehaviorRequestControl(oid='");
    buffer.append(PASSWORD_UPDATE_BEHAVIOR_REQUEST_OID);
    buffer.append("', isCritical=");
    buffer.append(isCritical());
    buffer.append(", properties=");
    new PasswordUpdateBehaviorRequestControlProperties(this).toString(buffer);
    buffer.append(')');
  }
}
