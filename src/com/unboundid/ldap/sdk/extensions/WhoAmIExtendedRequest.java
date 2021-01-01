/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.extensions;



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the LDAP "Who Am I?" extended
 * request as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc4532.txt">RFC 4532</A>.  It may be used
 * to request the current authorization identity associated with the client
 * connection.
 * <BR><BR>
 * The "Who Am I?" extended operation is similar to the
 * {@link com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl}
 * in that it can be used to request the authorization identity for the
 * connection.  The primary difference between them is that the authorization
 * identity request control can only be included in a bind request (and the
 * corresponding response control will be included in the bind result), while
 * the "Who Am I?" extended operation can be used at any time through a separate
 * operation.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the "Who Am I?" extended
 * operation.
 * <PRE>
 * // Use the "Who Am I?" extended request to determine the identity of the
 * // currently-authenticated user.
 * WhoAmIExtendedResult whoAmIResult;
 * try
 * {
 *   whoAmIResult = (WhoAmIExtendedResult)
 *        connection.processExtendedOperation(new WhoAmIExtendedRequest());
 *   // This doesn't necessarily mean that the operation was successful, since
 *   // some kinds of extended operations return non-success results under
 *   // normal conditions.
 * }
 * catch (LDAPException le)
 * {
 *   // For an extended operation, this generally means that a problem was
 *   // encountered while trying to send the request or read the result.
 *   whoAmIResult = new WhoAmIExtendedResult(new ExtendedResult(le));
 * }
 *
 * LDAPTestUtils.assertResultCodeEquals(whoAmIResult, ResultCode.SUCCESS);
 * String authzID = whoAmIResult.getAuthorizationID();
 * if (authzID.equals("") || authzID.equals("dn:"))
 * {
 *   // The user is authenticated anonymously.
 * }
 * else if (authzID.startsWith("dn:"))
 * {
 *   // The DN of the authenticated user should be authzID.substring(3)
 * }
 * else if (authzID.startsWith("u:"))
 * {
 *   // The username of the authenticated user should be authzID.substring(2)
 * }
 * else
 * {
 *   // The authorization ID isn't in any recognizable format.  Perhaps it's
 *   // a raw DN or a username?
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class WhoAmIExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.4203.1.11.3) for the "Who Am I?" extended request.
   */
  @NotNull public static final String WHO_AM_I_REQUEST_OID =
       "1.3.6.1.4.1.4203.1.11.3";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2936513698220673318L;



  /**
   * Creates a new "Who Am I?" extended request.
   */
  public WhoAmIExtendedRequest()
  {
    super(WHO_AM_I_REQUEST_OID);
  }



  /**
   * Creates a new "Who Am I?" extended request.
   *
   * @param  controls  The set of controls to include in the request.
   */
  public WhoAmIExtendedRequest(@Nullable final Control[] controls)
  {
    super(WHO_AM_I_REQUEST_OID, controls);
  }



  /**
   * Creates a new "Who Am I?" extended request from the provided generic
   * extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          "Who Am I?" extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public WhoAmIExtendedRequest(@NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    if (extendedRequest.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_WHO_AM_I_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public WhoAmIExtendedResult process(@NotNull final LDAPConnection connection,
                                      final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new WhoAmIExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public WhoAmIExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public WhoAmIExtendedRequest duplicate(@Nullable final Control[] controls)
  {
    final WhoAmIExtendedRequest r = new WhoAmIExtendedRequest(controls);
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
    return INFO_EXTENDED_REQUEST_NAME_WHO_AM_I.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("WhoAmIExtendedRequest(");

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append("controls={");
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
