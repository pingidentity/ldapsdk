/*
 * Copyright 2007-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2022 Ping Identity Corporation
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
 * Copyright (C) 2007-2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.controls;



import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the expiring expiring control as
 * described in draft-vchu-ldap-pwd-policy.  It may be used to indicate that the
 * authenticated user's password will expire in the near future.  The value of
 * this control includes the length of time in seconds until the user's
 * password actually expires.
 * <BR><BR>
 * No request control is required to trigger the server to send the password
 * expiring response control.  If the server supports the use of this control
 * and the user's password will expire within a time frame that the server
 * considers to be the near future, then it will be included in the bind
 * response returned to the client.
 * <BR><BR>
 * See the documentation for the {@link PasswordExpiredControl} to see an
 * example that demonstrates the use of both the password expiring and password
 * expired controls.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordExpiringControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (2.16.840.1.113730.3.4.5) for the password expiring response
   * control.
   */
  @NotNull public static final String PASSWORD_EXPIRING_OID =
       "2.16.840.1.113730.3.4.5";



  /**
   * The name of the field used to hold the seconds until expiration in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SECONDS_UNTIL_EXPIRATION =
       "seconds-until-expiration";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1250220480854441338L;



  // The length of time in seconds until the password expires.
  private final int secondsUntilExpiration;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  PasswordExpiringControl()
  {
    secondsUntilExpiration = -1;
  }



  /**
   * Creates a new password expiring control with the provided information.
   *
   * @param  secondsUntilExpiration  The length of time in seconds until the
   *                                 password expires.
   */
  public PasswordExpiringControl(final int secondsUntilExpiration)
  {
    super(PASSWORD_EXPIRING_OID, false,
          new ASN1OctetString(String.valueOf(secondsUntilExpiration)));

    this.secondsUntilExpiration = secondsUntilExpiration;
  }



  /**
   * Creates a new password expiring control with the provided information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         password expiring response control.
   */
  public PasswordExpiringControl(@NotNull final String oid,
                                 final boolean isCritical,
                                 @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_EXPIRING_NO_VALUE.get());
    }

    try
    {
      secondsUntilExpiration = Integer.parseInt(value.stringValue());
    }
    catch (final NumberFormatException nfe)
    {
      Debug.debugException(nfe);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_EXPIRING_VALUE_NOT_INTEGER.get(), nfe);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public PasswordExpiringControl decodeControl(
              @NotNull final String oid, final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new PasswordExpiringControl(oid, isCritical, value);
  }



  /**
   * Extracts a password expiring control from the provided result.
   *
   * @param  result  The result from which to retrieve the password expiring
   *                 control.
   *
   * @return  The password expiring control contained in the provided result, or
   *          {@code null} if the result did not contain a password expiring
   *          control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the password expiring control contained in
   *                         the provided result.
   */
  @Nullable()
  public static PasswordExpiringControl get(@NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(PASSWORD_EXPIRING_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof PasswordExpiringControl)
    {
      return (PasswordExpiringControl) c;
    }
    else
    {
      return new PasswordExpiringControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Retrieves the length of time in seconds until the password expires.
   *
   * @return  The length of time in seconds until the password expires.
   */
  public int getSecondsUntilExpiration()
  {
    return secondsUntilExpiration;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PW_EXPIRING.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              PASSWORD_EXPIRING_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_PW_EXPIRING.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(
                   new JSONField(JSON_FIELD_SECONDS_UNTIL_EXPIRATION,
                        secondsUntilExpiration))));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * password expiring control.
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
   * @return  The password expiring control that was decoded from the provided
   *          JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid password expiring control.
   */
  @NotNull()
  public static PasswordExpiringControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new PasswordExpiringControl(jsonControl.getOID(),
           jsonControl.getCriticality(), rawValue);
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final Integer secondsUntilExpiration =
         valueObject.getFieldAsInteger(JSON_FIELD_SECONDS_UNTIL_EXPIRATION);
    if (secondsUntilExpiration == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_EXPIRING_JSON_MISSING_SECONDS_UNTIL_EXPIRATION.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_SECONDS_UNTIL_EXPIRATION));
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_SECONDS_UNTIL_EXPIRATION);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_PW_EXPIRING_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new PasswordExpiringControl(secondsUntilExpiration);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PasswordExpiringControl(secondsUntilExpiration=");
    buffer.append(secondsUntilExpiration);
    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
