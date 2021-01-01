/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
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
 * This class provides an implementation of an extended request that may be used
 * to register a YubiKey OTP device with the Directory Server so that it may be
 * used to authenticate using the UNBOUNDID-YUBIKEY-OTP SASL mechanism.
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
 * This extended request has an OID of 1.3.6.1.4.1.30221.2.6.54, and it must
 * include a request value with the following encoding:
 * <BR><BR>
 * <PRE>
 *   RegisterYubiKeyOTPDeviceRequest ::= SEQUENCE {
 *        authenticationID     [0] OCTET STRING OPTIONAL,
 *        staticPassword       [1] OCTET STRING OPTIONAL,
 *        yubiKeyOTP           [2] OCTET STRING,
 *        ... }
 * </PRE>
 *
 *
 * @see  DeregisterYubiKeyOTPDeviceExtendedRequest
 * @see  com.unboundid.ldap.sdk.unboundidds.UnboundIDYubiKeyOTPBindRequest
 * @see  com.unboundid.ldap.sdk.unboundidds.RegisterYubiKeyOTPDevice
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RegisterYubiKeyOTPDeviceExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.54) for the register YubiKey OTP device
   * extended request.
   */
  @NotNull public static final String REGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.54";



  /**
   * The BER type for the authentication ID element of the request value
   * sequence.
   */
  private static final byte TYPE_AUTHENTICATION_ID = (byte) 0x80;



  /**
   * The BER type for the static password element of the request value sequence.
   */
  private static final byte TYPE_STATIC_PASSWORD = (byte) 0x81;



  /**
   * The BER type for the YubiKey OTP element of the request value sequence.
   */
  private static final byte TYPE_YUBIKEY_OTP = (byte) 0x82;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4833523148133015294L;



  // The static password for the request.
  @Nullable private final ASN1OctetString staticPassword;

  // The authentication ID for the request.
  @Nullable private final String authenticationID;

  // The YubiKey OTP for the request.
  @NotNull private final String yubiKeyOTP;



  /**
   * Creates a new register YubiKey OTP device extended request that will be
   * used to register a new device for the user as whom the underlying
   * connection is authenticated.
   *
   * @param  yubiKeyOTP  A one-time password generated by the YubiKey device to
   *                     be registered.  It must not be {@code null}.
   * @param  controls    The set of controls to include in the request.  It may
   *                     be {@code null} or empty if there should not be any
   *                     request controls.
   */
  public RegisterYubiKeyOTPDeviceExtendedRequest(
              @NotNull final String yubiKeyOTP,
              @Nullable final Control... controls)
  {
    this(null, (ASN1OctetString) null, yubiKeyOTP, controls);
  }



  /**
   * Creates a new register YubiKey OTP device extended request with the
   * provided information.
   *
   * @param  authenticationID  The authentication ID that identifies the user
   *                           for whom the YubiKey OTP device is to be
   *                           registered.  It may be {@code null} if the device
   *                           is to be registered for the user as whom the
   *                           underlying connection is authenticated.
   * @param  staticPassword    The static password of the user for whom the
   *                           device is to be registered.  It may be
   *                           {@code null} if the device is to be registered
   *                           for a user other than the user authenticated on
   *                           the underlying connection and the server is
   *                           configured to not require the target user's
   *                           static password in this case.
   * @param  yubiKeyOTP        A one-time password generated by the YubiKey
   *                           device to be registered.  It must not be
   *                           {@code null}.
   * @param  controls          The set of controls to include in the request.
   *                           It may be {@code null} or empty if there should
   *                           not be any request controls.
   */
  public RegisterYubiKeyOTPDeviceExtendedRequest(
              @Nullable final String authenticationID,
              @Nullable final String staticPassword,
              @NotNull final String yubiKeyOTP,
              @Nullable final Control... controls)
  {
    this(authenticationID, encodePassword(staticPassword), yubiKeyOTP,
         controls);
  }



  /**
   * Creates a new register YubiKey OTP device extended request with the
   * provided information.
   *
   * @param  authenticationID  The authentication ID that identifies the user
   *                           for whom the YubiKey OTP device is to be
   *                           registered.  It may be {@code null} if the device
   *                           is to be registered for the user as whom the
   *                           underlying connection is authenticated.
   * @param  staticPassword    The static password of the user for whom the
   *                           device is to be registered.  It may be
   *                           {@code null} if the device is to be registered
   *                           for a user other than the user authenticated on
   *                           the underlying connection and the server is
   *                           configured to not require the target user's
   *                           static password in this case.
   * @param  yubiKeyOTP        A one-time password generated by the YubiKey
   *                           device to be registered.  It must not be
   *                           {@code null}.
   * @param  controls          The set of controls to include in the request.
   *                           It may be {@code null} or empty if there should
   *                           not be any request controls.
   */
  public RegisterYubiKeyOTPDeviceExtendedRequest(
              @Nullable final String authenticationID,
              @Nullable final byte[] staticPassword,
              @NotNull final String yubiKeyOTP,
              @Nullable final Control... controls)
  {
    this(authenticationID, encodePassword(staticPassword), yubiKeyOTP,
         controls);
  }



  /**
   * Creates a new register YubiKey OTP device extended request with the
   * provided information.
   *
   * @param  authenticationID  The authentication ID that identifies the user
   *                           for whom the YubiKey OTP device is to be
   *                           registered.  It may be {@code null} if the device
   *                           is to be registered for the user as whom the
   *                           underlying connection is authenticated.
   * @param  staticPassword    The static password of the user for whom the
   *                           device is to be registered.  It may be
   *                           {@code null} if the device is to be registered
   *                           for a user other than the user authenticated on
   *                           the underlying connection and the server is
   *                           configured to not require the target user's
   *                           static password in this case.
   * @param  yubiKeyOTP        A one-time password generated by the YubiKey
   *                           device to be registered.  It must not be
   *                           {@code null}.
   * @param  controls          The set of controls to include in the request.
   *                           It may be {@code null} or empty if there should
   *                           not be any request controls.
   */
  private RegisterYubiKeyOTPDeviceExtendedRequest(
               @Nullable final String authenticationID,
               @Nullable final ASN1OctetString staticPassword,
               @NotNull final String yubiKeyOTP,
               @Nullable final Control... controls)
  {
    super(REGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
         encodeValue(authenticationID, staticPassword, yubiKeyOTP), controls);

    this.authenticationID = authenticationID;
    this.staticPassword   = staticPassword;
    this.yubiKeyOTP       = yubiKeyOTP;
  }



  /**
   * Creates a new register YubiKey OTP device extended request that is decoded
   * from the provided generic extended request.
   *
   * @param  request  The generic extended request to decode as a register
   *                  YubiKey OTP device request.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the provided request.
   */
  public RegisterYubiKeyOTPDeviceExtendedRequest(
              @NotNull final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_REGISTER_YUBIKEY_OTP_REQUEST_NO_VALUE.get());
    }

    try
    {
      String authID = null;
      ASN1OctetString staticPW = null;
      String otp = null;
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(value.getValue()).elements())
      {
        switch (e.getType())
        {
          case TYPE_AUTHENTICATION_ID:
            authID = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_STATIC_PASSWORD:
            staticPW = ASN1OctetString.decodeAsOctetString(e);
            break;
          case TYPE_YUBIKEY_OTP:
            otp = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_REGISTER_YUBIKEY_OTP_REQUEST_UNRECOGNIZED_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }

      if (otp == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_REGISTER_YUBIKEY_OTP_REQUEST_MISSING_OTP.get());
      }

      authenticationID = authID;
      staticPassword   = staticPW;
      yubiKeyOTP       = otp;
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
           ERR_REGISTER_YUBIKEY_OTP_REQUEST_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided password as an ASN.1 octet string suitable for
   * inclusion in the encoded request.
   *
   * @param  password  The password to be encoded.  It may be {@code null} if
   *                   no password should be included.  If it is
   *                   non-{@code null}, then it must be a string or a byte
   *                   array.
   *
   * @return  The encoded password, or {@code null} if no password was given.
   */
  @Nullable()
  static ASN1OctetString encodePassword(@Nullable final Object password)
  {
    if (password == null)
    {
      return null;
    }
    else if (password instanceof byte[])
    {
      return new ASN1OctetString(TYPE_STATIC_PASSWORD, (byte[]) password);
    }
    else
    {
      return new ASN1OctetString(TYPE_STATIC_PASSWORD,
           String.valueOf(password));
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended request.
   *
   * @param  authenticationID  The authentication ID that identifies the user
   *                           for whom the YubiKey OTP device is to be
   *                           registered.  It may be {@code null} if the device
   *                           is to be registered for the user as whom the
   *                           underlying connection is authenticated.
   * @param  staticPassword    The static password of the user for whom the
   *                           device is to be registered.  It may be
   *                           {@code null} if the device is to be registered
   *                           for a user other than the user authenticated on
   *                           the underlying connection and the server is
   *                           configured to not require the target user's
   *                           static password in this case.
   * @param  yubiKeyOTP        A one-time password generated by the YubiKey
   *                           device to be registered.  It must not be
   *                           {@code null}.
   *
   * @return  The ASN.1 octet string containing the encoded request value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @Nullable final String authenticationID,
               @Nullable final ASN1OctetString staticPassword,
               @NotNull final String yubiKeyOTP)
  {
    Validator.ensureNotNull(yubiKeyOTP);

    final ArrayList<ASN1Element> elements = new ArrayList<>(3);

    if (authenticationID != null)
    {
      elements.add(
           new ASN1OctetString(TYPE_AUTHENTICATION_ID, authenticationID));
    }

    if (staticPassword != null)
    {
      elements.add(staticPassword);
    }

    elements.add(new ASN1OctetString(TYPE_YUBIKEY_OTP, yubiKeyOTP));
    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the authentication ID that identifies the user for whom the
   * YubiKey OTP device is to be registered, if provided.
   *
   * @return  The authentication ID that identifies the target user, or
   *          {@code null} if the device is to be registered as the user as
   *          whom the underlying connection is authenticated.
   */
  @Nullable()
  public String getAuthenticationID()
  {
    return authenticationID;
  }



  /**
   * Retrieves the string representation of the static password for the target
   * user, if provided.
   *
   * @return  The string representation of the static password for the target
   *          user, or {@code null} if no static password was provided.
   */
  @Nullable()
  public String getStaticPasswordString()
  {
    if (staticPassword == null)
    {
      return null;
    }
    else
    {
      return staticPassword.stringValue();
    }
  }



  /**
   * Retrieves the bytes that comprise the static password for the target user,
   * if provided.
   *
   * @return  The bytes that comprise the static password for the target user,
   *          or {@code null} if no static password was provided.
   */
  @Nullable()
  public byte[] getStaticPasswordBytes()
  {
    if (staticPassword == null)
    {
      return null;
    }
    else
    {
      return staticPassword.getValue();
    }
  }



  /**
   * Retrieves a one-time password generated by the YubiKey device to be
   * registered.
   *
   * @return  A one-time password generated by the YubiKey device to be
   *          registered.
   */
  @NotNull()
  public String getYubiKeyOTP()
  {
    return yubiKeyOTP;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public RegisterYubiKeyOTPDeviceExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public RegisterYubiKeyOTPDeviceExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final RegisterYubiKeyOTPDeviceExtendedRequest r =
         new RegisterYubiKeyOTPDeviceExtendedRequest(authenticationID,
              staticPassword, yubiKeyOTP, controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_REGISTER_YUBIKEY_OTP_REQUEST_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RegisterYubiKeyOTPDeviceExtendedRequest(");

    if (authenticationID != null)
    {
      buffer.append("authenticationID='");
      buffer.append(authenticationID);
      buffer.append("', ");
    }

    buffer.append("staticPasswordProvided=");
    buffer.append(staticPassword != null);

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
