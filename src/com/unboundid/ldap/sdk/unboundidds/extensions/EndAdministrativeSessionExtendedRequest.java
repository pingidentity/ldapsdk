/*
 * Copyright 2011-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the end administrative session
 * extended request, which indicates that an administrative session created via
 * with the {@link StartAdministrativeSessionExtendedRequest} should be ended.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * This extended request has an OID of 1.3.6.1.4.1.30221.2.6.14, and it does not
 * take a value.
 * <BR><BR>
 * See the documentation for the
 * {@link StartAdministrativeSessionExtendedRequest} for more information about
 * creating and using administrative sessions.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class EndAdministrativeSessionExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.14) for the end administrative session
   * extended request.
   */
  public static final String END_ADMIN_SESSION_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.14";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1860335278876749499L;



  /**
   * Creates a new end administrative session extended request with the provided
   * information.
   *
   * @param  controls  The set of controls to include in the request.
   */
  public EndAdministrativeSessionExtendedRequest(final Control... controls)
  {
    super(END_ADMIN_SESSION_REQUEST_OID, controls);
  }



  /**
   * Creates a new end administrative session extended request from the provided
   * generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          end administrative session extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public EndAdministrativeSessionExtendedRequest(
              final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    if (extendedRequest.getValue() != null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_END_ADMIN_SESSION_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public EndAdministrativeSessionExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public EndAdministrativeSessionExtendedRequest duplicate(
              final Control[] controls)
  {
    return new EndAdministrativeSessionExtendedRequest(controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_END_ADMIN_SESSION.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("EndAdministrativeSessionExtendedRequest(");

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
