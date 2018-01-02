/*
 * Copyright 2012-2018 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the get subtree accessibility
 * extended request, which may be used to request information about all subtree
 * accessibility restrictions currently defined in the server, including for
 * subtrees that are hidden or read-only.  Subtree accessibility may be altered
 * using the {@link SetSubtreeAccessibilityExtendedRequest}.
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
 * This extended request has an OID of 1.3.6.1.4.1.30221.1.6.20 and does not
 * have a value.
 *
 * @see  GetSubtreeAccessibilityExtendedResult
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetSubtreeAccessibilityExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.1.6.20) for the get subtree accessibility
   * extended request.
   */
  public static final String GET_SUBTREE_ACCESSIBILITY_REQUEST_OID =
       "1.3.6.1.4.1.30221.1.6.20";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6519976409372387402L;



  /**
   * Creates a new get subtree accessibility extended request.
   *
   * @param  controls  The set of controls to include in the request.  It may be
   *                   {@code null} or empty if no controls are needed.
   */
  public GetSubtreeAccessibilityExtendedRequest(final Control... controls)
  {
    super(GET_SUBTREE_ACCESSIBILITY_REQUEST_OID, null, controls);
  }



  /**
   * Creates a new get subtree accessibility extended request from the provided
   * generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          get subtree accessibility extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public GetSubtreeAccessibilityExtendedRequest(
              final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    if (extendedRequest.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_SUBTREE_ACCESSIBILITY_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public GetSubtreeAccessibilityExtendedResult process(
              final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new GetSubtreeAccessibilityExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public GetSubtreeAccessibilityExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public GetSubtreeAccessibilityExtendedRequest duplicate(
                                                     final Control[] controls)
  {
    final GetSubtreeAccessibilityExtendedRequest r =
         new GetSubtreeAccessibilityExtendedRequest(controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_GET_SUBTREE_ACCESSIBILITY.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("GetSubtreeAccessibilityExtendedRequest(");

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
