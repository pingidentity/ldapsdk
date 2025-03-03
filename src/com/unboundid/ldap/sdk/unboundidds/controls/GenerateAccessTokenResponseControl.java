/*
 * Copyright 2023-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023-2025 Ping Identity Corporation
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
 * Copyright (C) 2023-2025 Ping Identity Corporation
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



import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectTrio;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a response control that may be used to convey the
 * access token (and other associated information) generated in response to a
 * {@link GenerateAccessTokenRequestControl} for a successful bind operation.
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
 * This control has an OID of "1.3.6.1.4.1.30221.2.5.68", a criticality of
 * false, and a value that is the string representation of a JSON object with
 * the following fields:
 * <UL>
 *   <LI>
 *     {@code token} -- The access token that was generated by the server.  This
 *     field may be absent if an error occurred while attempting to generate the
 *     access token.
 *   </LI>
 *   <LI>
 *     {@code expiration-time} -- The time that the access token is expected to
 *     expire.  If present, it will be formatted in the ISO 8601 format
 *     described in RFC 3339 (which may be decoded using the
 *     {@link StaticUtils#decodeRFC3339Time} method).  If absent, then the
 *     access token may not expire.
 *   </LI>
 *   <LI>
 *     {@code error-message} -- An optional message that may explain the reason
 *     that an access token could not be generated for the request.
 *   </LI>
 * </UL>
 *
 * @see  GenerateAccessTokenRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GenerateAccessTokenResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.68) for the generate access token response
   * control.
   */
  @NotNull public static final String GENERATE_ACCESS_TOKEN_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.68";



  /**
   * The name of the field used to hold the generated access token in the value
   * of this control.
   */
  @NotNull private static final String JSON_FIELD_ACCESS_TOKEN = "token";



  /**
   * The name of the field used to hold the error message in the value of this
   * control.
   */
  @NotNull private static final String JSON_FIELD_ERROR_MESSAGE =
       "error-message";



  /**
   * The name of the field used to hold the access token expiration time in the
   * value of this control.
   */
  @NotNull private static final String JSON_FIELD_EXPIRATION_TIME =
       "expiration-time";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6071943602038789356L;



  // The access token expiration time included in the control.
  @Nullable private final Long expirationTime;

  // The generated access token included in the control.
  @Nullable private final String accesToken;

  // The error message included in the control.
  @Nullable private final String errorMessage;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  GenerateAccessTokenResponseControl()
  {
    expirationTime = null;
    accesToken = null;
    errorMessage = null;
  }



  /**
   * Creates a new generate access token response control with the provided
   * information.
   *
   * @param  accessToken     The access token that was generated.  It may be
   *                         {@code null} if no access token was generated.
   * @param  expirationTime  The time that the access token is expected to
   *                         expire.  It may be {@code null} if no access token
   *                         was generated, or if the token does not have an
   *                         expiration time.
   * @param  errorMessage    An error message with the reason the access token
   *                         was not generated.  It may be {@code null} if the
   *                         access token was generated successfully or if no
   *                         error message is available.
   */
  public GenerateAccessTokenResponseControl(
              @Nullable final String accessToken,
              @Nullable final Date expirationTime,
              @Nullable final String errorMessage)
  {
    super(GENERATE_ACCESS_TOKEN_RESPONSE_OID, false,
         new ASN1OctetString(encodeValueObject(accessToken, expirationTime,
              errorMessage).toString()));

    this.accesToken = accessToken;
    this.errorMessage = errorMessage;

    if (expirationTime == null)
    {
      this.expirationTime = null;
    }
    else
    {
      this.expirationTime = expirationTime.getTime();
    }
  }



  /**
   * Creates a new generate access token response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         generate access token response control.
   */
  public GenerateAccessTokenResponseControl(
              @NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical,  value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GENERATE_ACCESS_TOKEN_RESPONSE_NO_VALUE.get());
    }

    try
    {
      final JSONObject valueObject =  new JSONObject(value.stringValue());
      final ObjectTrio<String,Date,String> valueElements =
           decodeJSONObject(valueObject);
      accesToken = valueElements.getFirst();
      errorMessage = valueElements.getThird();

      final Date expirationTimeDate = valueElements.getSecond();
      if (expirationTimeDate == null)
      {
        expirationTime = null;
      }
      else
      {
        expirationTime = expirationTimeDate.getTime();
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GENERATE_ACCESS_TOKEN_RESPONSE_CANNOT_DECODE_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Decodes the provided JSON object as the value of a generate access token
   * response control.
   *
   * @param  valueObject  The JSON object to use to decode the value of a
   *                      generate access token response control.  It must not
   *                      be {@code null}.
   *
   * @return  An {@code ObjectTrio} in which the first element is the access
   *          token, the second element is the expiration time, and the third
   *          element is the error message.  Any or all of the elements may be
   *          {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         JSON object as a generate access token value.
   */
  @NotNull()
  private static ObjectTrio<String,Date,String> decodeJSONObject(
               @NotNull final JSONObject valueObject)
          throws LDAPException
  {
    final String accessToken =
         valueObject.getFieldAsString(JSON_FIELD_ACCESS_TOKEN);
    final String errorMessage =
         valueObject.getFieldAsString(JSON_FIELD_ERROR_MESSAGE);

    final Date expirationTime;
    final String expirationTimeStr =
         valueObject.getFieldAsString(JSON_FIELD_EXPIRATION_TIME);
    if (expirationTimeStr == null)
    {
      expirationTime = null;
    }
    else
    {
      try
      {
        expirationTime = StaticUtils.decodeRFC3339Time(expirationTimeStr);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_GENERATE_ACCESS_TOKEN_RESPONSE_INVALID_TIMESTAMP.get(
                  valueObject.toSingleLineString(),
                  JSON_FIELD_EXPIRATION_TIME));
      }
    }

    return new ObjectTrio<>(accessToken, expirationTime, errorMessage);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GenerateAccessTokenResponseControl decodeControl(
              @NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new GenerateAccessTokenResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts a generate access token response control from the provided result.
   *
   * @param  result  The result from which to retrieve the generate access token
   *                 response control.
   *
   * @return  The generate access token response control contained in the
   *          provided result, or {@code null} if the result did not contain a
   *          generate access token response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the generate access token response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static GenerateAccessTokenResponseControl get(
              @NotNull final BindResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(GENERATE_ACCESS_TOKEN_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof GenerateAccessTokenResponseControl)
    {
      return (GenerateAccessTokenResponseControl) c;
    }
    else
    {
      return new GenerateAccessTokenResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Encodes the provided information into a JSON object suitable for use in
   * the value of this control.
   *
   * @param  accessToken     The access token that was generated.  It may be
   *                         {@code null} if no access token was generated.
   * @param  expirationTime  The time that the access token is expected to
   *                         expire.  It may be {@code null} if no access token
   *                         was generated, or if the token does not have an
   *                         expiration time.
   * @param  errorMessage    An error message containing the reason the access
   *                         token was not generated.  It may be {@code null} if
   *                         the access token was generated successfully or if
   *                         no error message is available.
   *
   * @return  A JSON object containing the encoded control value information.
   */
  @NotNull()
  private static JSONObject encodeValueObject(
               @Nullable final String accessToken,
               @Nullable final Date expirationTime,
               @Nullable final String errorMessage)
  {
    return encodeValueObject(accessToken,
         ((expirationTime == null) ? null : expirationTime.getTime()),
         errorMessage);
  }



  /**
   * Encodes the provided information into a JSON object suitable for use in
   * the value of this control.
   *
   * @param  accessToken     The access token that was generated.  It may be
   *                         {@code null} if no access token was generated.
   * @param  expirationTime  The time that the access token is expected to
   *                         expire.  It may be {@code null} if no access token
   *                         was generated, or if the token does not have an
   *                         expiration time.
   * @param  errorMessage    An error message containing the reason the access
   *                         token was not generated.  It may be {@code null} if
   *                         the access token was generated successfully or if
   *                         no error message is available.
   *
   * @return  A JSON object containing the encoded control value information.
   */
  @NotNull()
  private static JSONObject encodeValueObject(
               @Nullable final String accessToken,
               @Nullable final Long expirationTime,
               @Nullable final String errorMessage)
  {
    final Map<String,JSONValue> fields =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(3));

    if (accessToken != null)
    {
      fields.put(JSON_FIELD_ACCESS_TOKEN, new JSONString(accessToken));
    }

    if (expirationTime != null)
    {
      fields.put(JSON_FIELD_EXPIRATION_TIME,
           new JSONString(StaticUtils.encodeRFC3339Time(expirationTime)));
    }

    if (errorMessage != null)
    {
      fields.put(JSON_FIELD_ERROR_MESSAGE, new JSONString(errorMessage));
    }

    return new JSONObject(fields);
  }



  /**
   * Retrieves the access token that was generated by the server.
   *
   * @return  The access token that was generated by the server, or {@code null}
   *          if no access token was generated..
   */
  @Nullable()
  public String getAccessToken()
  {
    return accesToken;
  }



  /**
   * Retrieves the time that the generated access token is expected to expire.
   *
   * @return  The time that the generated access token is expected to expire, or
   *          {@code null} if no access token was generated or if it does not
   *          have an expiration time.
   */
  @Nullable()
  public Date getExpirationTime()
  {
    if (expirationTime == null)
    {
      return null;
    }
    else
    {
      return new Date(expirationTime);
    }
  }



  /**
   * Retrieves an error message with the reason the access token was not
   * generated.
   *
   * @return  An error message with the reason the access token was not
   *          generated, or {@code null} if the access token was generated
   *          successfully or if no error message is available.
   */
  @Nullable()
  public String getErrorMessage()
  {
    return errorMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GENERATE_ACCESS_TOKEN_RESPONSE.get();
  }



  /**
   * Retrieves a representation of this generate access token response control
   * as a JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the generate access token response
   *     control, the OID is "1.3.6.1.4.1.30221.2.5.68".
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
   *     base64-encoded representation of the raw value for this generate access
   *     token response control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this generate access
   *     token response control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code token} -- An optional string field whose value is the access
   *         token that was generated.
   *       </LI>
   *       <LI>
   *         {@code expiration-time} -- An optional string field whose value is
   *         a timestamp indicating the time that the access token will expire,
   *         using the ISO 8601 format described in RFC 3339.
   *       </LI>
   *       <LI>
   *         {@code error-message} -- An optional string field whose value is an
   *         error message with the reason the access token was not generated.
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
    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              GENERATE_ACCESS_TOKEN_RESPONSE_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_GENERATE_ACCESS_TOKEN_RESPONSE.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              encodeValueObject(accesToken, expirationTime, errorMessage)));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * generate access token response control.
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
   * @return  The generate access token response control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid generate access token response control.
   */
  @NotNull()
  public static GenerateAccessTokenResponseControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new GenerateAccessTokenResponseControl(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue);
    }


    final JSONObject valueObject = jsonControl.getValueObject();
    final ObjectTrio<String,Date,String> valueElements =
         decodeJSONObject(valueObject);

    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_ACCESS_TOKEN,
                JSON_FIELD_EXPIRATION_TIME, JSON_FIELD_ERROR_MESSAGE);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_GENERATE_TOKEN_RESPONSE_JSON_CONTROL_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new GenerateAccessTokenResponseControl(valueElements.getFirst(),
         valueElements.getSecond(), valueElements.getThird());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GenerateAccessTokenResponseControl(hasAccessToken=");
    buffer.append(accesToken != null);

    if (expirationTime != null)
    {
      buffer.append(", expirationTime='");
      buffer.append(StaticUtils.encodeRFC3339Time(expirationTime));
      buffer.append('\'');
    }

    if (errorMessage != null)
    {
      buffer.append(", errorMessage='");
      buffer.append(errorMessage);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
