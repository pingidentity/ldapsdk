/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request that may be sent
 * to the Ping Identity Directory Server to determine whether a provided
 * password is correct for a user without performing any other password policy
 * processing for that user.  The server will not make any attempt to determine
 * whether the target user's account is in a usable state, nor will it update
 * the user's password policy state information in any way as a result of the
 * verification attempt.
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
 * The extended request has an OID of 1.3.6.1.4.1.30221.2.6.72. The request must
 * have a value, which will be encoded as a JSON object with the following
 * fields:
 * <UL>
 *   <LI>
 *     {@code dn} -- The DN of the user for whom to make the determination.
 *     This field is required to be present.
 *   </LI>
 *   <LI>
 *     {@code password} -- The password to verify for the user.  This field is
 *     required to be present.
 * </UL>
 * <BR>
 * For security purposes, the server will only allow this request to be issued
 * by a client with the necessary access control permission to do so, and who
 * also has the {@code permit-verify-password-request} privilege.  And by
 * default, the server will only permit clients to issue verify password
 * requests over a secure connection.
 * <BR><BR>
 * In response to a verify password extended request, the server will return a
 * generic extended response with no OID or value.  The result code included in
 * that response should provide a suitable indication of the outcome, and in
 * some cases, a diagnostic message may provide additional details about any
 * issue that the server encountered.  Some of the result codes that may be
 * returned in response to a verify password extended request include:
 * <BR>
 * <UL>
 *   <LI>
 *     {@link ResultCode#COMPARE_TRUE} -- All processing completed successfully,
 *     and the provided password was correct for the target user.
 *   </LI>
 *   <LI>
 *     {@link ResultCode#COMPARE_FALSE} -- All processing completed
 *     successfully, but the provided password was not correct for the target
 *     user.
 *   </LI>
 *   <LI>
 *     {@link ResultCode#NO_SUCH_OBJECT} -- If the entry for the target user
 *     does not exist.
 *   </LI>
 *   <LI>
 *     {@link ResultCode#INVALID_DN_SYNTAX} -- If the target user DN cannot be
 *     parsed as a valid DN.
 *   </LI>
 *   <LI>
 *     {@link ResultCode#INAPPROPRIATE_AUTHENTICATION} -- If the target user
 *     does not have a password.
 *   </LI>
 *   <LI>
 *     {@link ResultCode#INSUFFICIENT_ACCESS_RIGHTS} -- If the requester does
 *     not have the necessary access control permission to issue the request,
 *     or if they do not have the {@code permit-verify-password-request}
 *     privilege.
 *   </LI>
 *   <LI>
 *     {@link ResultCode#CONFIDENTIALITY_REQUIRED} -- If the client is using an
 *     insecure connection, but the server requires secure communication for the
 *     request.
 *   </LI>
 *   <LI>
 *     {@link ResultCode#OTHER} -- If an internal error occurred while
 *     attempting to process the request.
 *   </LI>
 * </UL>
 * <BR>
 * <H2>Example</H2>
 * The following example demonstrates how to use the verify password extended
 * request to determine whether a password is correct for a user without
 * performing any password policy processing that would normally occur for a
 * bind operation:
 * <BR><BR>
 * <PRE>
 *   public static boolean isPasswordValidForUser(
 *               final LDAPConnection connection,
 *               final String targetUserDN,
 *               final String passwordToVerify)
 *          throws LDAPException
 *   {
 *     final VerifyPasswordExtendedRequest verifyPasswordRequest =
 *          new VerifyPasswordExtendedRequest(targetUserDN, passwordToVerify);
 *
 *     LDAPResult verifyPasswordResult;
 *     try
 *     {
 *       verifyPasswordResult =
 *            connection.processExtendedOperation(verifyPasswordRequest);
 *     }
 *     catch (final LDAPException e)
 *     {
 *       verifyPasswordResult = e.toLDAPResult();
 *     }
 *
 *     final ResultCode resultCode = verifyPasswordResult.getResultCode();
 *     if (resultCode == ResultCode.COMPARE_TRUE)
 *     {
 *       // The provided password is correct for the target user.
 *       return true;
 *     }
 *     else if (resultCode == ResultCode.COMPARE_FALSE)
 *     {
 *       // The provided password is not correct for the target user.
 *       return false;
 *     }
 *     else
 *     {
 *       // An error occurred while trying to verify the password.
 *       throw new LDAPException(verifyPasswordResult);
 *     }
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class VerifyPasswordExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.72) for the verify password extended
   * request.
   */
  @NotNull public static final String VERIFY_PASSWORD_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.72";



  /**
   * The name of the JSON field used to specify the DN of the user for whom
   * to make the determination.
   */
  @NotNull public static final String REQUEST_FIELD_DN = "dn";



  /**
   * The name of the JSON field used to specify the password for which to make
   * the determination.
   */
  @NotNull public static final String REQUEST_FIELD_PASSWORD = "password";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4632159563446607461L;



  // The DN of the user for whom to make the determination.
  @NotNull private final String dn;

  // The password of the user for whom to make the determination.
  @NotNull private final String password;



  /**
   * Creates a new verify password extended request with the provided
   * information.
   *
   * @param  dn        The DN of the user for whom to make the determination.
   *                   It must not be {@code null} or empty.
   * @param  password  The password for which to make the determination.  It
   *                   must not be {@code null} or empty.
   * @param  controls  An optional set of controls to include in the extended
   *                   request.  It may be {@code null} or empty if no controls
   *                   are needed.
   */
  public VerifyPasswordExtendedRequest(@NotNull final String dn,
                                       @NotNull final String password,
                                       @Nullable final Control... controls)
  {
    super(VERIFY_PASSWORD_REQUEST_OID, encodeValue(dn, password), controls);

    this.dn = dn;
    this.password = password;
  }



  /**
   * Encodes the provided information into a form sufficient for use as the
   * value of this extended request.
   *
   * @param  dn        The DN of the user for whom to make the determination.
   *                   It must not be {@code null} or empty.
   * @param  password  The password for which to make the determination.  It
   *                   must not be {@code null} or empty.
   *
   * @return  An ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String dn,
                                             @NotNull final String password)
  {
    Validator.ensureNotNullOrEmpty(dn,
         "VerifyPasswordExtendedRequest.dn must not be null or empty");
    Validator.ensureNotNullOrEmpty(password,
         "VerifyPasswordExtendedRequest.password must not be null or empty");

    final JSONObject requestObject = new JSONObject(
         new JSONField(REQUEST_FIELD_DN, dn),
         new JSONField(REQUEST_FIELD_PASSWORD, password));

    return new ASN1OctetString(requestObject.toSingleLineString());
  }



  /**
   * Attempts to decode the provided generic extended request as a verify
   * password extended request.
   *
   * @param  extendedRequest  The generic extended request to decode as a verify
   *                          password request.  It must not be {@code null}.
   *
   * @throws  LDAPException  If the provided request cannot be decoded as a
   *                         verify password request.
   */
  public VerifyPasswordExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VERIFY_PASSWORD_REQUEST_NO_VALUE.get());
    }

    final JSONObject requestObject;
    try
    {
      requestObject = new JSONObject(value.stringValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VERIFY_PASSWORD_REQUEST_CANNOT_DECODE_VALUE.get());
    }

    dn = requestObject.getFieldAsString(REQUEST_FIELD_DN);
    if (dn == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VERIFY_PASSWORD_REQUEST_MISSING_FIELD.get(REQUEST_FIELD_DN));
    }
    else if (dn.isEmpty())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VERIFY_PASSWORD_REQUEST_EMPTY_FIELD.get(REQUEST_FIELD_DN));
    }

    password = requestObject.getFieldAsString(REQUEST_FIELD_PASSWORD);
    if (password == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VERIFY_PASSWORD_REQUEST_MISSING_FIELD.get(
                REQUEST_FIELD_PASSWORD));
    }
    else if (password.isEmpty())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VERIFY_PASSWORD_REQUEST_EMPTY_FIELD.get(REQUEST_FIELD_PASSWORD));
    }
  }



  /**
   * Retrieves the DN of the user for whom to verify the password.
   *
   * @return  The DN of the user for whom to verify the password.
   */
  @NotNull()
  public String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the password to attempt to verify for the user.
   *
   * @return  The password to attempt to verify for the user.
   */
  @NotNull()
  public String getPassword()
  {
    return password;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public VerifyPasswordExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public VerifyPasswordExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final VerifyPasswordExtendedRequest r =
         new VerifyPasswordExtendedRequest(dn, password, controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    r.setIntermediateResponseListener(getIntermediateResponseListener());
    r.setReferralDepth(getReferralDepth());
    r.setReferralConnector(getReferralConnectorInternal());
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_VERIFY_PASSWORD.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("VerifyPasswordExtendedRequest(dn='");
    buffer.append(dn);
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
