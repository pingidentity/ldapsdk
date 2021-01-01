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
package com.unboundid.ldap.sdk.controls;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the proxied authorization V2
 * request control, as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc4370.txt">RFC 4370</A>.  It may be used
 * to request that the associated operation be performed as if it has been
 * requested by some other user.
 * <BR><BR>
 * The target authorization identity for this control is specified as an
 * "authzId" value as described in section 5.2.1.8 of
 * <A HREF="http://www.ietf.org/rfc/rfc4513.txt">RFC 4513</A>.  That is, it
 * should be either "dn:" followed by the distinguished name of the target user,
 * or "u:" followed by the username.  If the "u:" form is used, then the
 * mechanism used to resolve the provided username to an entry may vary from
 * server to server.
 * <BR><BR>
 * This control may be used in conjunction with add, delete, compare, delete,
 * extended, modify, modify DN, and search requests.  In that case, the
 * associated operation will be processed under the authority of the specified
 * authorization identity rather than the identity associated with the client
 * connection (i.e., the user as whom that connection is bound).  Note that
 * because of the inherent security risks associated with the use of the proxied
 * authorization control, most directory servers which support its use enforce
 * strict restrictions on the users that are allowed to request this control.
 * If a user attempts to use the proxied authorization V2 request control and
 * does not have sufficient permission to do so, then the server will return a
 * failure response with the {@link ResultCode#AUTHORIZATION_DENIED} result
 * code.
 * <BR><BR>
 * There is no corresponding response control for this request control.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the proxied authorization V2
 * control to delete an entry under the authority of the user with username
 * "alternate.user":
 * <PRE>
 * // Create a delete request to delete an entry.  Include the proxied
 * // authorization v2 request control in the delete request so that the
 * // delete will be processed as the user with username "alternate.user"
 * // instead of the user that's actually authenticated on the connection.
 * DeleteRequest deleteRequest =
 *      new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com");
 * deleteRequest.addControl(new ProxiedAuthorizationV2RequestControl(
 *      "u:alternate.user"));
 *
 * LDAPResult deleteResult;
 * try
 * {
 *   deleteResult = connection.delete(deleteRequest);
 *   // If we got here, then the delete was successful.
 * }
 * catch (LDAPException le)
 * {
 *   // The delete failed for some reason.  In addition to all of the normal
 *   // reasons a delete could fail (e.g., the entry doesn't exist, or has one
 *   // or more subordinates), proxied-authorization specific failures may
 *   // include that the authenticated user doesn't have permission to use the
 *   // proxied authorization control to impersonate the alternate user, that
 *   // the alternate user doesn't exist, or that the alternate user doesn't
 *   // have permission to perform the requested operation.
 *   deleteResult = le.toLDAPResult();
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ProxiedAuthorizationV2RequestControl
       extends Control
{
  /**
   * The OID (2.16.840.1.113730.3.4.18) for the proxied authorization v2 request
   * control.
   */
  @NotNull public static final String PROXIED_AUTHORIZATION_V2_REQUEST_OID =
       "2.16.840.1.113730.3.4.18";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1054244283964851067L;



  // The authorization ID string that may be used to identify the user under
  // whose authorization the associated operation should be performed.
  @NotNull private final String authorizationID;



  /**
   * Creates a new proxied authorization V2 request control that will proxy as
   * the specified user.
   *
   * @param  authorizationID  The authorization ID string that will be used to
   *                          identify the user under whose authorization the
   *                          associated operation should be performed.  It may
   *                          take one of three forms:  it can be an empty
   *                          string (to indicate that the operation should use
   *                          anonymous authorization), a string that begins
   *                          with "dn:" and is followed by the DN of the target
   *                          user, or a string that begins with "u:" and is
   *                          followed by the username for the target user
   *                          (where the process of mapping the provided
   *                          username to the corresponding entry will depend on
   *                          the server configuration).  It must not be
   *                          {@code null}.
   */
  public ProxiedAuthorizationV2RequestControl(
              @NotNull final String authorizationID)
  {
    super(PROXIED_AUTHORIZATION_V2_REQUEST_OID, true,
          new ASN1OctetString(authorizationID));

    Validator.ensureNotNull(authorizationID);

    this.authorizationID = authorizationID;
  }



  /**
   * Creates a new proxied authorization v2 request control which is decoded
   * from the provided generic control.
   *
   * @param  control  The generic control to be decoded as a proxied
   *                  authorization v2 request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         proxied authorization v2 request control.
   */
  public ProxiedAuthorizationV2RequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PROXY_V2_NO_VALUE.get());
    }

    authorizationID = value.stringValue();
  }



  /**
   * Retrieves the authorization ID string that will be used to identify the
   * user under whose authorization the associated operation should be
   * performed.
   *
   * @return  The authorization ID string that will be used to identify the user
   *          under whose authorization the associated operation should be
   *          performed.
   */
  @NotNull()
  public String getAuthorizationID()
  {
    return authorizationID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PROXIED_AUTHZ_V2_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ProxiedAuthorizationV2RequestControl(authorizationID='");
    buffer.append(authorizationID);
    buffer.append("')");
  }
}
