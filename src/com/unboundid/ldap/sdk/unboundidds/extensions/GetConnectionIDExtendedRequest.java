/*
 * Copyright 2008-2018 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.unboundidds.controls.
            IntermediateClientRequestControl;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the get connection ID extended
 * operation as used in the Ping Identity, UnboundID, and Alcatel-Lucent 8661
 * Directory Server.  It may be used to obtain the connection ID associated with
 * the current connection.  This is primarily useful for debugging purposes, and
 * the {@link IntermediateClientRequestControl} may also be used to obtain this
 * (along with other information).
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
 * This extended request has an OID of 1.3.6.1.4.1.30221.1.6.2.  It does not
 * have a value.
 * <BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for using the get connection
 * ID extended operation:
 * <PRE>
 * GetConnectionIDExtendedResult result =
 *      (GetConnectionIDExtendedResult) connection.processExtendedOperation(
 *           new GetConnectionIDExtendedRequest());
 *
 * // NOTE:  The processExtendedOperation method will generally only throw an
 * // exception if a problem occurs while trying to send the request or read
 * // the response.  It will not throw an exception because of a non-success
 * // response.
 *
 * if (result.getResultCode() == ResultCode.SUCCESS)
 * {
 *   long connectionID = result.getConnectionID();
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetConnectionIDExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.1.6.2) for the get connection ID extended
   * request.
   */
  public static final String GET_CONNECTION_ID_REQUEST_OID =
       "1.3.6.1.4.1.30221.1.6.2";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4787797927715098127L;



  // This is an ugly hack to prevent checkstyle from complaining about the
  // import for the IntermediateClientRequestControl class.  It is used by the
  // @link element in the javadoc, but checkstyle apparently doesn't recognize
  // that so we just need to use it in some way in this class to placate
  // checkstyle.
  static
  {
    final IntermediateClientRequestControl c = null;
  }



  /**
   * Creates a new get connection ID extended request with no controls.
   */
  public GetConnectionIDExtendedRequest()
  {
    this((Control[]) null);
  }



  /**
   * Creates a new get connection ID extended request with the provided set of
   * controls.
   *
   * @param  controls  The set of controls to include in the request.
   */
  public GetConnectionIDExtendedRequest(final Control[] controls)
  {
    super(GET_CONNECTION_ID_REQUEST_OID, null, controls);
  }



  /**
   * Creates a new get connection ID extended request from the provided generic
   * extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          get connection ID extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public GetConnectionIDExtendedRequest(final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    if (extendedRequest.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_GET_CONN_ID_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public GetConnectionIDExtendedResult process(final LDAPConnection connection,
                                               final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new GetConnectionIDExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public GetConnectionIDExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public GetConnectionIDExtendedRequest duplicate(final Control[] controls)
  {
    final GetConnectionIDExtendedRequest r =
         new GetConnectionIDExtendedRequest(controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_GET_CONNECTION_ID.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("GetConnectionIDExtendedRequest(");

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
