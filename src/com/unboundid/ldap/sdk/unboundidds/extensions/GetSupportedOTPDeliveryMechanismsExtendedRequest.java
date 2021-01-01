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



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request that can be used
 * to retrieve information about which one-time password delivery mechanisms are
 * supported for a user.
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
 * The OID for this extended request is "1.3.6.1.4.1.30221.2.6.47".  It must
 * have a value with the following encoding:
 * <BR><BR>
 * <PRE>
 *   GetSupportedOTPDeliveryMechanismsRequest ::= SEQUENCE {
 *        userDN     [0] LDAPDN,
 *        ... }
 * </PRE>
 *
 * @see  GetSupportedOTPDeliveryMechanismsExtendedResult
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetSupportedOTPDeliveryMechanismsExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.47) for the get supported one-time password
   * delivery mechanisms extended request.
   */
  @NotNull public static final String
       GET_SUPPORTED_OTP_DELIVERY_MECHANISMS_REQUEST_OID =
            "1.3.6.1.4.1.30221.2.6.47";



  /**
   * The BER type for the userDN element.
   */
  private static final byte TYPE_USER_DN = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1670631089524097883L;



  // THe DN of the user for whom to retrieve the supported delivery mechanisms.
  @NotNull private final String userDN;



  /**
   * Creates a new instance of this get supported OTP delivery mechanisms
   * extended request with the provided information.
   *
   * @param  userDN    The DN of the user for whom to retrieve the list of
   *                   supported OTP delivery mechanisms.  It must not be
   *                   {@code null}.
   * @param  controls  The set of controls to include in the request.  It may be
   *                   {@code null} or empty if no controls should be included.
   */
  public GetSupportedOTPDeliveryMechanismsExtendedRequest(
              @NotNull final String userDN,
              @Nullable final Control... controls)
  {
    super(GET_SUPPORTED_OTP_DELIVERY_MECHANISMS_REQUEST_OID,
         encodeValue(userDN), controls);

    this.userDN = userDN;
  }



  /**
   * Decodes the provided extended request as a get supported OTP delivery
   * mechanisms request.
   *
   * @param  request  The extended request to be decoded as a get supported OTP
   *                  delivery mechanisms request.
   *
   * @throws  LDAPException  If the provided request cannot be decoded as a get
   *                         supported OTP delivery mechanisms request.
   */
  public GetSupportedOTPDeliveryMechanismsExtendedRequest(
              @NotNull final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_SUPPORTED_OTP_MECH_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      userDN = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_SUPPORTED_OTP_MECH_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value for this extended operation.
   *
   * @param  userDN  The DN of the user for whom to retrieve the list of
   *                 supported OTP delivery mechanisms.  It must not be
   *                 {@code null}.
   *
   * @return  The ASN.1 octet string containing the encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String userDN)
  {
    return new ASN1OctetString(new ASN1Sequence(
         new ASN1OctetString(TYPE_USER_DN, userDN)).encode());
  }



  /**
   * Retrieves the DN of the user for whom to retrieve the list of supported OTP
   * delivery mechanisms.
   *
   * @return  The DN of the user for whom to retrieve the list of supported OTP
   *          delivery mechanisms.
   */
  @NotNull()
  public String getUserDN()
  {
    return userDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetSupportedOTPDeliveryMechanismsExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new GetSupportedOTPDeliveryMechanismsExtendedResult(
         extendedResponse);
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  @NotNull()
  public GetSupportedOTPDeliveryMechanismsExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  @NotNull()
  public GetSupportedOTPDeliveryMechanismsExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final GetSupportedOTPDeliveryMechanismsExtendedRequest r =
         new GetSupportedOTPDeliveryMechanismsExtendedRequest(userDN,
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
    return INFO_GET_SUPPORTED_OTP_MECH_REQ_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetSupportedOTPDeliveryMechanismsExtendedRequest(userDN='");
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
