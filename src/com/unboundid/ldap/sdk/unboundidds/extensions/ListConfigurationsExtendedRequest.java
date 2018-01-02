/*
 * Copyright 2013-2018 Ping Identity Corporation
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request that can be used
 * to retrieve a list of all available versions of the configuration within a
 * server.  This may include not only the currently-active configuration, but
 * also former configurations that have been archived, and the baseline
 * configuration for the current server version.
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
 * The OID for this extended request is 1.3.6.1.4.1.30221.2.6.26.  It does not
 * have a value.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for using the list
 * configurations and get configuration extended requests to obtain the oldest
 * archived configuration from the server:
 * <PRE>
 * // Get a list of the available configurations from the server.
 * ListConfigurationsExtendedResult listConfigsResult =
 *      (ListConfigurationsExtendedResult)
 *      connection.processExtendedOperation(
 *           new ListConfigurationsExtendedRequest());
 * String archivedConfigFileName =
 *      listConfigsResult.getArchivedFileNames().get(0);
 *
 * // Retrieve the first archived configuration from the list configurations
 * // result.
 * GetConfigurationExtendedResult getConfigResult =
 *      (GetConfigurationExtendedResult)
 *      connection.processExtendedOperation(GetConfigurationExtendedRequest.
 *           createGetArchivedConfigurationRequest(archivedConfigFileName));
 *
 * InputStream fileDataStream = getConfigResult.getFileDataInputStream();
 * // Read data from the file.
 * fileDataStream.close();
 * </PRE>
 *
 * @see  GetConfigurationExtendedRequest
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ListConfigurationsExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.26) for the list configurations extended
   * request.
   */
  public static final  String LIST_CONFIGS_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.26";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5511054471842622735L;



  /**
   * Creates a new list configurations extended request with the provided
   * information.
   *
   * @param  controls  An optional set of controls to include in the request.
   *                   This may be {@code null} or empty if no controls should
   *                   be included in the request.
   */
  public ListConfigurationsExtendedRequest(final Control... controls)
  {
    super(LIST_CONFIGS_REQUEST_OID, controls);
  }



  /**
   * Creates a new list configurations extended request that has been decoded
   * from the provided generic extended request.
   *
   * @param  r  The generic extended request to decode as a list configurations
   *            extended request.
   *
   * @throws LDAPException  If the provided request cannot be decoded as a
   *                         valid list configurations extended request.
   */
  public ListConfigurationsExtendedRequest(final ExtendedRequest r)
         throws LDAPException
  {
    super(r);

    if (r.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LIST_CONFIGS_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ListConfigurationsExtendedResult process(
              final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new ListConfigurationsExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ListConfigurationsExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ListConfigurationsExtendedRequest duplicate(
              final Control[] controls)
  {
    final ListConfigurationsExtendedRequest r =
         new ListConfigurationsExtendedRequest(controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_LIST_CONFIGS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ListConfigurationsExtendedRequest(");

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
