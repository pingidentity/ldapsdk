/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
 * This class provides an implementation of an extended request which may be
 * used to validate a TOTP password for a user.  Note that this should not be
 * used as an alternative to authentication because it does not perform password
 * policy processing.  Rather, this extended operation should be used only to
 * obtain additional assurance about the identity of a user that has already
 * been authenticated through some other means.
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
 * The extended request has an OID of 1.3.6.1.4.1.30221.2.6.15 and a value with
 * the following encoding:
 * <PRE>
 *   ValidateTOTPPasswordRequest ::= SEQUENCE {
 *        userDN           [0] LDAPDN,
 *        totpPassword     [1] OCTET STRING,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ValidateTOTPPasswordExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.15) for the validate TOTP password extended
   * request.
   */
  @NotNull public static final String VALIDATE_TOTP_PASSWORD_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.15";



  /**
   * The BER type for the user DN value element.
   */
  private static final byte TYPE_USER_DN = (byte) 0x80;



  /**
   * The BER type for the TOTP password value element.
   */
  private static final byte TYPE_TOTP_PASSWORD = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4610279612454559569L;



  // The DN of the user for whom to validate the TOTP password.
  @NotNull private final String userDN;

  // The TOTP password to validate.
  @NotNull private final String totpPassword;



  /**
   * Creates a new validate TOTP password extended request with the provided
   * information.
   *
   * @param  userDN        The DN of the user for whom to validate the TOTP
   *                       password.
   * @param  totpPassword  The TOTP password to validate.
   * @param  controls      The set of controls to include in the request.
   */
  public ValidateTOTPPasswordExtendedRequest(
              @NotNull final String userDN,
              @NotNull final String totpPassword,
              @Nullable final Control... controls)
  {
    super(VALIDATE_TOTP_PASSWORD_REQUEST_OID,
         encodeValue(userDN, totpPassword), controls);

    Validator.ensureNotNull(userDN);
    Validator.ensureNotNull(totpPassword);

    this.userDN       = userDN;
    this.totpPassword = totpPassword;
  }



  /**
   * Creates a new validate TOTP password extended request from the provided
   * generic extended request.
   *
   * @param  extendedRequest  The generic extended request to parse as a
   *                          validate TOTP extended request.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         parse the provided extended request.
   */
  public ValidateTOTPPasswordExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VALIDATE_TOTP_REQUEST_MISSING_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      userDN = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
      totpPassword =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VALIDATE_TOTP_REQUEST_MALFORMED_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into a value suitable for use as the value
   * for this extended request.
   *
   * @param  userDN        The DN of the user for whom to validate the TOTP
   *                       password.
   * @param  totpPassword  The TOTP password to validate.
   *
   * @return  The ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final String userDN,
                      @NotNull final String totpPassword)
  {
    return new ASN1OctetString(new ASN1Sequence(
         new ASN1OctetString(TYPE_USER_DN, userDN),
         new ASN1OctetString(TYPE_TOTP_PASSWORD, totpPassword)).encode());
  }



  /**
   * Retrieves the DN of the user for whom to validate the TOTP password.
   *
   * @return  The DN of the user for whom to validate the TOTP password.
   */
  @NotNull()
  public String getUserDN()
  {
    return userDN;
  }



  /**
   * Retrieves the TOTP password to validate.
   *
   * @return  The TOTP password to validate.
   */
  @NotNull()
  public String getTOTPPassword()
  {
    return totpPassword;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ValidateTOTPPasswordExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ValidateTOTPPasswordExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final ValidateTOTPPasswordExtendedRequest r =
         new ValidateTOTPPasswordExtendedRequest(userDN, totpPassword,
              controls);
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
    return INFO_EXTENDED_REQUEST_NAME_VALIDATE_TOTP.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ValidateTOTPPasswordExtendedRequest(userDN='");
    buffer.append(userDN);
    buffer.append('\'');

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
