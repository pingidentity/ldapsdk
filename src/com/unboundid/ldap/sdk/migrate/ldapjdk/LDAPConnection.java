/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.AsyncRequestID;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.CompareResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.UpdatableLDAPRequest;
import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an object that may be used to communicate with an LDAP
 * directory server.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the
 * {@link com.unboundid.ldap.sdk.LDAPConnection} class should be used instead.
 */
@Mutable()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPConnection
{
  /**
   * The integer value for the DEREF_NEVER dereference policy.
   */
  public static final int DEREF_NEVER = DereferencePolicy.NEVER.intValue();



  /**
   * The integer value for the DEREF_SEARCHING dereference policy.
   */
  public static final int DEREF_SEARCHING =
       DereferencePolicy.SEARCHING.intValue();



  /**
   * The integer value for the DEREF_FINDING dereference policy.
   */
  public static final int DEREF_FINDING =
       DereferencePolicy.FINDING.intValue();



  /**
   * The integer value for the DEREF_ALWAYS dereference policy.
   */
  public static final int DEREF_ALWAYS =
       DereferencePolicy.ALWAYS.intValue();



  /**
   * The integer value for the SCOPE_BASE search scope.
   */
  public static final int SCOPE_BASE = SearchScope.BASE_INT_VALUE;



  /**
   * The integer value for the SCOPE_ONE search scope.
   */
  public static final int SCOPE_ONE = SearchScope.ONE_INT_VALUE;



  /**
   * The integer value for the SCOPE_SUB search scope.
   */
  public static final int SCOPE_SUB = SearchScope.SUB_INT_VALUE;



  // The connection used to perform the actual communication with the server.
  @NotNull private volatile com.unboundid.ldap.sdk.LDAPConnection conn;

  // The default constraints that will be used for non-search operations.
  @NotNull private LDAPConstraints constraints;

  // The set of controls returned from the last operation.
  @Nullable private LDAPControl[] responseControls;

  // The default constraints that will be used for search operations.
  @NotNull private LDAPSearchConstraints searchConstraints;

  // The socket factory for this connection.
  @Nullable private LDAPSocketFactory socketFactory;

  // The DN last used to bind to the server.
  @Nullable private String authDN;

  // The password last used to bind to the server.
  @Nullable private String authPW;



  /**
   * Creates a new LDAP connection which will use the default socket factory.
   */
  public LDAPConnection()
  {
    this(null);
  }



  /**
   * Creates a new LDAP connection which will use the provided socket factory.
   *
   * @param  socketFactory  The socket factory to use when creating the socket
   *                        to use for communicating with the server.
   */
  public LDAPConnection(@Nullable final LDAPSocketFactory socketFactory)
  {
    this.socketFactory = socketFactory;
    if (socketFactory == null)
    {
      conn = new com.unboundid.ldap.sdk.LDAPConnection();
    }
    else
    {

      conn = new com.unboundid.ldap.sdk.LDAPConnection(
           new LDAPToJavaSocketFactory(socketFactory));
    }

    authDN = null;
    authPW = null;

    constraints       = new LDAPConstraints();
    searchConstraints = new LDAPSearchConstraints();
  }



  /**
   * Closes the connection to the server if the client forgets to do so.
   *
   * @throws  Throwable  If a problem occurs.
   */
  @Override()
  protected void finalize()
            throws Throwable
  {
    conn.close();

    super.finalize();
  }



  /**
   * Retrieves the {@link com.unboundid.ldap.sdk.LDAPConnection} object used to
   * back this connection.
   *
   * @return  The {@code com.unboundid.ldap.sdk.LDAPConnection} object used to
   *          back this connection.
   */
  @NotNull()
  public com.unboundid.ldap.sdk.LDAPConnection getSDKConnection()
  {
    return conn;
  }



  /**
   * Retrieves the address to which the connection is established.
   *
   * @return  The address to which the connection is established.
   */
  @Nullable()
  public String getHost()
  {
    return conn.getConnectedAddress();
  }



  /**
   * Retrieves the port to which the connection is established.
   *
   * @return  The port to which the connection is established.
   */
  public int getPort()
  {
    return conn.getConnectedPort();
  }



  /**
   * Retrieves the DN of the user that last authenticated on this connection.
   *
   * @return  The DN of the user that last authenticated on this connection,
   *          or {@code null} if it is not available.
   */
  @Nullable()
  public String getAuthenticationDN()
  {
    return authDN;
  }



  /**
   * Retrieves the password of the user that last authenticated on this
   * connection.
   *
   * @return  The password of the user that last authenticated on this
   *           connection, or {@code null} if it is not available.
   */
  @Nullable()
  public String getAuthenticationPassword()
  {
    return authPW;
  }



  /**
   * Retrieves the maximum length of time to wait for the connection to be
   * established, in seconds.
   *
   * @return  The maximum length of time to wait for the connection to be
   *          established.
   */
  public int getConnectTimeout()
  {
    final int connectTimeoutMillis =
         conn.getConnectionOptions().getConnectTimeoutMillis();
    if (connectTimeoutMillis > 0)
    {
      return Math.max(1, (connectTimeoutMillis / 1000));
    }
    else
    {
      return 0;
    }
  }



  /**
   * Specifies the maximum length of time to wait for the connection to be
   * established, in seconds.
   *
   * @param  timeout  The maximum length of time to wait for the connection to
   *                  be established.
   */
  public void setConnectTimeout(final int timeout)
  {
    final LDAPConnectionOptions options = conn.getConnectionOptions();

    if (timeout > 0)
    {
      options.setConnectTimeoutMillis(1000 * timeout);
    }
    else
    {
      options.setConnectTimeoutMillis(0);
    }

    conn.setConnectionOptions(options);
  }



  /**
   * Retrieves the socket factory for this LDAP connection, if specified.
   *
   * @return  The socket factory for this LDAP connection, or {@code null} if
   *          none has been provided.
   */
  @Nullable()
  public LDAPSocketFactory getSocketFactory()
  {
    return socketFactory;
  }



  /**
   * Sets the socket factory for this LDAP connection.
   *
   * @param  socketFactory  The socket factory for this LDAP connection.
   */
  public void setSocketFactory(@Nullable final LDAPSocketFactory socketFactory)
  {
    this.socketFactory = socketFactory;

    if (socketFactory == null)
    {
      conn.setSocketFactory(null);
    }
    else
    {
      conn.setSocketFactory(new LDAPToJavaSocketFactory(socketFactory));
    }
  }



  /**
   * Retrieves the constraints for this connection.
   *
   * @return  The constraints for this connection.
   */
  @NotNull()
  public LDAPConstraints getConstraints()
  {
    return constraints;
  }



  /**
   * Updates the constraints for this connection.
   *
   * @param  constraints  The constraints for this connection.
   */
  public void setConstraints(@Nullable final LDAPConstraints constraints)
  {
    if (constraints == null)
    {
      this.constraints = new LDAPConstraints();
    }
    else
    {
      this.constraints = constraints;
    }
  }



  /**
   * Retrieves the search constraints for this connection.
   *
   * @return  The search constraints for this connection.
   */
  @NotNull()
  public LDAPSearchConstraints getSearchConstraints()
  {
    return searchConstraints;
  }



  /**
   * Updates the search constraints for this connection.
   *
   * @param  searchConstraints  The search constraints for this connection.
   */
  public void setSearchConstraints(
                   @Nullable final LDAPSearchConstraints searchConstraints)
  {
    if (searchConstraints == null)
    {
      this.searchConstraints = new LDAPSearchConstraints();
    }
    else
    {
      this.searchConstraints = searchConstraints;
    }
  }



  /**
   * Retrieves the response controls from the last operation processed on this
   * connection.
   *
   * @return  The response controls from the last operation processed on this
   *          connection, or {@code null} if there were none.
   */
  @Nullable()
  public LDAPControl[] getResponseControls()
  {
    return responseControls;
  }



  /**
   * Indicates whether this connection is currently established.
   *
   * @return  {@code true} if this connection is currently established, or
   *          {@code false} if not.
   */
  public boolean isConnected()
  {
    return conn.isConnected();
  }



  /**
   * Attempts to establish this connection with the provided information.
   *
   * @param  host  The address of the server to which the connection should be
   *               established.
   * @param  port  The port of the server to which the connection should be
   *               established.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         this connection.
   */
  public void connect(@NotNull final String host, final int port)
         throws LDAPException
  {
    authDN           = null;
    authPW           = null;
    responseControls = null;

    try
    {
      conn.close();
      if (socketFactory == null)
      {
        conn = new com.unboundid.ldap.sdk.LDAPConnection(host, port);
      }
      else
      {

        conn = new com.unboundid.ldap.sdk.LDAPConnection(
             new LDAPToJavaSocketFactory(socketFactory), host, port);
      }
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Attempts to establish and authenticate this connection with the provided
   * information.
   *
   * @param  host      The address of the server to which the connection should
   *                   be established.
   * @param  port      The port of the server to which the connection should be
   *                   established.
   * @param  dn        The DN to use to bind to the server.
   * @param  password  The password to use to bind to the server.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         or authenticate this connection.  If an exception
   *                         is thrown, then the connection will not be
   *                         established.
   */
  public void connect(@NotNull final String host, final int port,
                      @Nullable final String dn,
                      @Nullable final String password)
         throws LDAPException
  {
    connect(3, host, port, dn, password, null);
  }



  /**
   * Attempts to establish and authenticate this connection with the provided
   * information.
   *
   * @param  host         The address of the server to which the connection
   *                      should be established.
   * @param  port         The port of the server to which the connection should
   *                      be established.
   * @param  dn           The DN to use to bind to the server.
   * @param  password     The password to use to bind to the server.
   * @param  constraints  The constraints to use when processing the bind.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         or authenticate this connection.  If an exception
   *                         is thrown, then the connection will not be
   *                         established.
   */
  public void connect(@NotNull final String host, final int port,
                      @Nullable final String dn,
                      @Nullable final String password,
                      @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    connect(3, host, port, dn, password, constraints);
  }



  /**
   * Attempts to establish and authenticate this connection with the provided
   * information.
   *
   * @param  version   The LDAP protocol version to use for the connection.
   *                   This will be ignored, since this implementation only
   *                   supports LDAPv3.
   * @param  host      The address of the server to which the connection should
   *                   be established.
   * @param  port      The port of the server to which the connection should be
   *                   established.
   * @param  dn        The DN to use to bind to the server.
   * @param  password  The password to use to bind to the server.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         or authenticate this connection.  If an exception
   *                         is thrown, then the connection will not be
   *                         established.
   */
  public void connect(final int version, @NotNull final String host,
                      final int port, @Nullable final String dn,
                      @Nullable final String password)
         throws LDAPException
  {
    connect(version, host, port, dn, password, null);
  }



  /**
   * Attempts to establish and authenticate this connection with the provided
   * information.
   *
   * @param  version      The LDAP protocol version to use for the connection.
   *                      This will be ignored, since this implementation only
   *                      supports LDAPv3.
   * @param  host         The address of the server to which the connection
   *                      should be established.
   * @param  port         The port of the server to which the connection should
   *                      be established.
   * @param  dn           The DN to use to bind to the server.
   * @param  password     The password to use to bind to the server.
   * @param  constraints  The constraints to use when processing the bind.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         or authenticate this connection.  If an exception
   *                         is thrown, then the connection will not be
   *                         established.
   */
  public void connect(final int version, @NotNull final String host,
                      final int port, @Nullable final String dn,
                      @Nullable final String password,
                      @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    connect(host, port);

    try
    {
      if ((dn != null) && (password != null))
      {
        bind(version, dn, password, constraints);
      }
    }
    catch (final LDAPException le)
    {
      conn.close();
      throw le;
    }
  }



  /**
   * Unbinds and disconnects from the directory server.
   *
   * @throws  LDAPException  If a problem occurs.
   */
  public void disconnect()
         throws LDAPException
  {
    authDN = null;
    authPW = null;

    conn.close();
    if (socketFactory == null)
    {
      conn = new com.unboundid.ldap.sdk.LDAPConnection();
    }
    else
    {

      conn = new com.unboundid.ldap.sdk.LDAPConnection(
           new LDAPToJavaSocketFactory(socketFactory));
    }
  }



  /**
   * Disconnects from the directory server and attempts to re-connect and
   * re-authenticate.
   *
   * @throws  LDAPException  If a problem occurs.  If an exception is thrown,
   *                         the connection will have been closed.
   */
  public void reconnect()
         throws LDAPException
  {
    final String host = getHost();
    final int    port = getPort();
    final String dn   = authDN;
    final String pw   = authPW;

    if ((dn == null) || (pw == null))
    {
      connect(host, port);
    }
    else
    {
      connect(host, port, dn, pw);
    }
  }



  /**
   * Sends a request to abandon the request with the specified message ID.
   *
   * @param  id  The message ID of the operation to abandon.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public void abandon(final int id)
         throws LDAPException
  {
    try
    {
      conn.abandon(InternalSDKHelper.createAsyncRequestID(id, conn),
                   getControls(null));
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Sends a request to abandon the provided search operation.
   *
   * @param  searchResults  The search results object for the search to abandon.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public void abandon(@NotNull final LDAPSearchResults searchResults)
         throws LDAPException
  {
    try
    {
      final AsyncRequestID requestID = searchResults.getAsyncRequestID();
      if (requestID != null)
      {
        searchResults.setAbandoned();
        conn.abandon(requestID);
      }
      else
      {
        // This should never happen.
        throw new LDAPException(
             "The search request has not been sent to the server",
             LDAPException.PARAM_ERROR);
      }
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Adds the provided entry to the directory.
   *
   * @param  entry  The entry to be added.
   *
   * @throws  LDAPException  If a problem occurs while adding the entry.
   */
  public void add(@NotNull final LDAPEntry entry)
         throws LDAPException
  {
    add(entry, null);
  }



  /**
   * Adds the provided entry to the directory.
   *
   * @param  entry        The entry to be added.
   * @param  constraints  The constraints to use for the add operation.
   *
   * @throws  LDAPException  If a problem occurs while adding the entry.
   */
  public void add(@NotNull final LDAPEntry entry,
                  @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    final AddRequest addRequest = new AddRequest(entry.toEntry());
    update(addRequest, constraints);

    try
    {
      final LDAPResult result = conn.add(addRequest);
      setResponseControls(result);
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Authenticates to the directory server using a simple bind with the provided
   * information.
   *
   * @param  dn        The DN of the user for the bind.
   * @param  password  The password to use for the bind.
   *
   * @throws  LDAPException  If the bind attempt fails.
   */
  public void authenticate(@Nullable final String dn,
                           @Nullable final String password)
         throws LDAPException
  {
    bind(3, dn, password, null);
  }



  /**
   * Authenticates to the directory server using a simple bind with the provided
   * information.
   *
   * @param  dn           The DN of the user for the bind.
   * @param  password     The password to use for the bind.
   * @param  constraints  The constraints to use for the bind operation.
   *
   * @throws  LDAPException  If the bind attempt fails.
   */
  public void authenticate(@Nullable final String dn,
                           @Nullable final String password,
                           @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    bind(3, dn, password, constraints);
  }



  /**
   * Authenticates to the directory server using a simple bind with the provided
   * information.
   *
   * @param  version   The LDAP protocol version to use.  This will be ignored,
   *                   since this implementation only supports LDAPv3.
   * @param  dn        The DN of the user for the bind.
   * @param  password  The password to use for the bind.
   *
   * @throws  LDAPException  If the bind attempt fails.
   */
  public void authenticate(final int version, @Nullable final String dn,
                           @Nullable final String password)
         throws LDAPException
  {
    bind(version, dn, password, null);
  }



  /**
   * Authenticates to the directory server using a simple bind with the provided
   * information.
   *
   * @param  version      The LDAP protocol version to use.  This will be
   *                      ignored, since this implementation only supports
   *                      LDAPv3.
   * @param  dn           The DN of the user for the bind.
   * @param  password     The password to use for the bind.
   * @param  constraints  The constraints to use for the bind operation.
   *
   * @throws  LDAPException  If the bind attempt fails.
   */
  public void authenticate(final int version, @Nullable final String dn,
                           @Nullable final String password,
                           @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    bind(version, dn, password, constraints);
  }



  /**
   * Authenticates to the directory server using a simple bind with the provided
   * information.
   *
   * @param  dn        The DN of the user for the bind.
   * @param  password  The password to use for the bind.
   *
   * @throws  LDAPException  If the bind attempt fails.
   */
  public void bind(@Nullable final String dn, @Nullable final String password)
         throws LDAPException
  {
    bind(3, dn, password, null);
  }



  /**
   * Authenticates to the directory server using a simple bind with the provided
   * information.
   *
   * @param  dn           The DN of the user for the bind.
   * @param  password     The password to use for the bind.
   * @param  constraints  The constraints to use for the bind operation.
   *
   * @throws  LDAPException  If the bind attempt fails.
   */
  public void bind(@Nullable final String dn, @Nullable final String password,
                   @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    bind(3, dn, password, constraints);
  }



  /**
   * Authenticates to the directory server using a simple bind with the provided
   * information.
   *
   * @param  version   The LDAP protocol version to use.  This will be ignored,
   *                   since this implementation only supports LDAPv3.
   * @param  dn        The DN of the user for the bind.
   * @param  password  The password to use for the bind.
   *
   * @throws  LDAPException  If the bind attempt fails.
   */
  public void bind(final int version, @Nullable final String dn,
                   @Nullable final String password)
         throws LDAPException
  {
    bind(version, dn, password, null);
  }



  /**
   * Authenticates to the directory server using a simple bind with the provided
   * information.
   *
   * @param  version      The LDAP protocol version to use.  This will be
   *                      ignored, since this implementation only supports
   *                      LDAPv3.
   * @param  dn           The DN of the user for the bind.
   * @param  password     The password to use for the bind.
   * @param  constraints  The constraints to use for the bind operation.
   *
   * @throws  LDAPException  If the bind attempt fails.
   */
  public void bind(final int version, @Nullable final String dn,
                   @Nullable final String password,
                   @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    final SimpleBindRequest bindRequest =
         new SimpleBindRequest(dn, password, getControls(constraints));
    authDN = null;
    authPW = null;

    try
    {
      final BindResult bindResult = conn.bind(bindRequest);
      setResponseControls(bindResult);
      if (bindResult.getResultCode() == ResultCode.SUCCESS)
      {
        authDN = dn;
        authPW = password;
      }
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Indicates whether the specified entry has the given attribute value.
   *
   * @param  dn         The DN of the entry to compare.
   * @param  attribute  The attribute (which must have exactly one value) to use
   *                    for the comparison.
   *
   * @return  {@code true} if the compare matched the target entry, or
   *          {@code false} if not.
   *
   * @throws  LDAPException  If a problem occurs while processing the compare.
   */
  public boolean compare(@NotNull final String dn,
                         @NotNull final LDAPAttribute attribute)
         throws LDAPException
  {
    return compare(dn, attribute, null);
  }



  /**
   * Indicates whether the specified entry has the given attribute value.
   *
   * @param  dn           The DN of the entry to compare.
   * @param  attribute    The attribute (which must have exactly one value) to
   *                      use for the comparison.
   * @param  constraints  The constraints to use for the compare operation.
   *
   * @return  {@code true} if the compare matched the target entry, or
   *          {@code false} if not.
   *
   * @throws  LDAPException  If a problem occurs while processing the compare.
   */
  public boolean compare(@NotNull final String dn,
                         @NotNull final LDAPAttribute attribute,
                         @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    final CompareRequest compareRequest = new CompareRequest(dn,
         attribute.getName(), attribute.getByteValueArray()[0]);
    update(compareRequest, constraints);

    try
    {
      final CompareResult result = conn.compare(compareRequest);
      setResponseControls(result);
      return result.compareMatched();
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Removes an entry from the directory.
   *
   * @param  dn  The DN of the entry to delete.
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void delete(@NotNull final String dn)
         throws LDAPException
  {
    delete(dn, null);
  }



  /**
   * Removes an entry from the directory.
   *
   * @param  dn           The DN of the entry to delete.
   * @param  constraints  The constraints to use for the delete operation.
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void delete(@NotNull final String dn,
                     @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    final DeleteRequest deleteRequest = new DeleteRequest(dn);
    update(deleteRequest, constraints);

    try
    {
      final LDAPResult result = conn.delete(deleteRequest);
      setResponseControls(result);
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Processes an extended operation in the directory.
   *
   * @param  extendedOperation  The extended operation to process.
   *
   * @return  The result returned from the extended operation.
   *
   * @throws  LDAPException  If a problem occurs while processing the operation.
   */
  @NotNull()
  public LDAPExtendedOperation extendedOperation(
              @NotNull final LDAPExtendedOperation extendedOperation)
         throws LDAPException
  {
    return extendedOperation(extendedOperation,  null);
  }



  /**
   * Processes an extended operation in the directory.
   *
   * @param  extendedOperation  The extended operation to process.
   * @param  constraints        The constraints to use for the operation.
   *
   * @return  The result returned from the extended operation.
   *
   * @throws  LDAPException  If a problem occurs while processing the operation.
   */
  @NotNull()
  public LDAPExtendedOperation extendedOperation(
              @NotNull final LDAPExtendedOperation extendedOperation,
              @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    final ExtendedRequest extendedRequest = new ExtendedRequest(
         extendedOperation.getID(),
         new ASN1OctetString(extendedOperation.getValue()),
         getControls(constraints));

    try
    {
      final ExtendedResult result =
           conn.processExtendedOperation(extendedRequest);
      setResponseControls(result);

      if (result.getResultCode() != ResultCode.SUCCESS)
      {
        throw new LDAPException(result.getDiagnosticMessage(),
             result.getResultCode().intValue(), result.getDiagnosticMessage(),
             result.getMatchedDN());
      }

      final byte[] valueBytes;
      final ASN1OctetString value = result.getValue();
      if (value == null)
      {
        valueBytes = null;
      }
      else
      {
        valueBytes = value.getValue();
      }

      return new LDAPExtendedOperation(result.getOID(), valueBytes);
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Modifies an entry in the directory.
   *
   * @param  dn   The DN of the entry to modify.
   * @param  mod  The modification to apply to the entry.
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void modify(@NotNull final String dn,
                     @NotNull final LDAPModification mod)
         throws LDAPException
  {
    modify(dn, new LDAPModification[] { mod }, null);
  }



  /**
   * Modifies an entry in the directory.
   *
   * @param  dn    The DN of the entry to modify.
   * @param  mods  The modifications to apply to the entry.
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void modify(@NotNull final String dn,
                     @NotNull final LDAPModification[] mods)
         throws LDAPException
  {
    modify(dn, mods, null);
  }



  /**
   * Modifies an entry in the directory.
   *
   * @param  dn           The DN of the entry to modify.
   * @param  mod          The modification to apply to the entry.
   * @param  constraints  The constraints to use for the modify operation.
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void modify(@NotNull final String dn,
                     @NotNull final LDAPModification mod,
                     @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    modify(dn, new LDAPModification[] { mod }, constraints);
  }



  /**
   * Modifies an entry in the directory.
   *
   * @param  dn           The DN of the entry to modify.
   * @param  mods         The modifications to apply to the entry.
   * @param  constraints  The constraints to use for the modify operation.
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void modify(@NotNull final String dn,
                     @NotNull final LDAPModification[] mods,
                     @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    final Modification[] m = new Modification[mods.length];
    for (int i=0; i < mods.length; i++)
    {
      m[i] = mods[i].toModification();
    }

    final ModifyRequest modifyRequest = new ModifyRequest(dn, m);
    update(modifyRequest, constraints);

    try
    {
      final LDAPResult result = conn.modify(modifyRequest);
      setResponseControls(result);
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Modifies an entry in the directory.
   *
   * @param  dn    The DN of the entry to modify.
   * @param  mods  The modifications to apply to the entry.
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void modify(@NotNull final String dn,
                     @NotNull final LDAPModificationSet mods)
         throws LDAPException
  {
    modify(dn, mods.toArray(), null);
  }



  /**
   * Modifies an entry in the directory.
   *
   * @param  dn           The DN of the entry to modify.
   * @param  mods         The modifications to apply to the entry.
   * @param  constraints  The constraints to use for the modify operation.
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void modify(@NotNull final String dn,
                     @NotNull final LDAPModificationSet mods,
                     @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    modify(dn, mods.toArray(), constraints);
  }



  /**
   * Retrieves an entry from the directory server.
   *
   * @param  dn  The DN of the entry to retrieve.
   *
   * @return  The entry that was read.
   *
   * @throws  LDAPException  If a problem occurs while performing the search.
   */
  @NotNull()
  public LDAPEntry read(@NotNull final String dn)
         throws LDAPException
  {
    return read(dn, null, null);
  }



  /**
   * Retrieves an entry from the directory server.
   *
   * @param  dn           The DN of the entry to retrieve.
   * @param  constraints  The constraints to use for the search operation.
   *
   * @return  The entry that was read.
   *
   * @throws  LDAPException  If a problem occurs while performing the search.
   */
  @NotNull()
  public LDAPEntry read(@NotNull final String dn,
                        @Nullable final LDAPSearchConstraints constraints)
         throws LDAPException
  {
    return read(dn, null, constraints);
  }



  /**
   * Retrieves an entry from the directory server.
   *
   * @param  dn     The DN of the entry to retrieve.
   * @param  attrs  The set of attributes to request.
   *
   * @return  The entry that was read.
   *
   * @throws  LDAPException  If a problem occurs while performing the search.
   */
  @NotNull()
  public LDAPEntry read(@NotNull final String dn,
                        @Nullable final String[] attrs)
         throws LDAPException
  {
    return read(dn, attrs, null);
  }



  /**
   * Retrieves an entry from the directory server.
   *
   * @param  dn           The DN of the entry to retrieve.
   * @param  attrs        The set of attributes to request.
   * @param  constraints  The constraints to use for the search operation.
   *
   * @return  The entry that was read.
   *
   * @throws  LDAPException  If a problem occurs while performing the search.
   */
  @NotNull()
  public LDAPEntry read(@NotNull final String dn,
                        @Nullable final String[] attrs,
                        @Nullable final LDAPSearchConstraints constraints)
         throws LDAPException
  {
    final Filter filter = Filter.createORFilter(
         Filter.createPresenceFilter("objectClass"),
         Filter.createEqualityFilter("objectClass", "ldapSubentry"));

    final SearchRequest searchRequest =
         new SearchRequest(dn, SearchScope.BASE, filter, attrs);
    update(searchRequest, constraints);

    try
    {
      final SearchResult searchResult = conn.search(searchRequest);
      setResponseControls(searchResult);

      if (searchResult.getEntryCount() != 1)
      {
        throw new LDAPException(null, LDAPException.NO_RESULTS_RETURNED);
      }

      return new LDAPEntry(searchResult.getSearchEntries().get(0));
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Alters the DN of an entry in the directory.
   *
   * @param  dn            The DN of the entry to modify.
   * @param  newRDN        The new RDN to use for the entry.
   * @param  deleteOldRDN  Indicates whether to remove the old RDN value(s).
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void rename(@NotNull final String dn, @NotNull final String newRDN,
                     final boolean deleteOldRDN)
         throws LDAPException
  {
    rename(dn, newRDN, null, deleteOldRDN, null);
  }



  /**
   * Alters the DN of an entry in the directory.
   *
   * @param  dn            The DN of the entry to modify.
   * @param  newRDN        The new RDN to use for the entry.
   * @param  deleteOldRDN  Indicates whether to remove the old RDN value(s).
   * @param  constraints   The constraints to use for the modify operation.
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void rename(@NotNull final String dn, @NotNull final String newRDN,
                     final boolean deleteOldRDN,
                     @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    rename(dn, newRDN, null, deleteOldRDN, constraints);
  }



  /**
   * Alters the DN of an entry in the directory.
   *
   * @param  dn            The DN of the entry to modify.
   * @param  newRDN        The new RDN to use for the entry.
   * @param  newParentDN   The DN of the new parent, or {@code null} if it
   *                       should not be moved below a new parent.
   * @param  deleteOldRDN  Indicates whether to remove the old RDN value(s).
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void rename(@NotNull final String dn, @NotNull final String newRDN,
                     @Nullable final String newParentDN,
                     final boolean deleteOldRDN)
         throws LDAPException
  {
    rename(dn, newRDN, newParentDN, deleteOldRDN, null);
  }



  /**
   * Alters the DN of an entry in the directory.
   *
   * @param  dn            The DN of the entry to modify.
   * @param  newRDN        The new RDN to use for the entry.
   * @param  newParentDN   The DN of the new parent, or {@code null} if it
   *                       should not be moved below a new parent.
   * @param  deleteOldRDN  Indicates whether to remove the old RDN value(s).
   * @param  constraints   The constraints to use for the modify operation.
   *
   * @throws  LDAPException  If a problem occurs while processing the delete.
   */
  public void rename(@NotNull final String dn, @NotNull final String newRDN,
                     @Nullable final String newParentDN,
                     final boolean deleteOldRDN,
                     @Nullable final LDAPConstraints constraints)
         throws LDAPException
  {
    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest(dn, newRDN, deleteOldRDN, newParentDN);
    update(modifyDNRequest, constraints);

    try
    {
      final LDAPResult result = conn.modifyDN(modifyDNRequest);
      setResponseControls(result);
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Processes a search in the directory server.
   *
   * @param  baseDN       The base DN for the search.
   * @param  scope        The scope for the search.
   * @param  filter       The filter for the search.
   * @param  attributes   The set of attributes to request.
   * @param  typesOnly    Indicates whether to return attribute types only or
   *                      both types and values.
   *
   * @return  The entry that was read.
   *
   * @throws  LDAPException  If a problem occurs while performing the search.
   */
  @NotNull()
  public LDAPSearchResults search(@NotNull final String baseDN, final int scope,
              @NotNull final String filter,
              @Nullable final String[] attributes,
              final boolean typesOnly)
         throws LDAPException
  {
    return search(baseDN, scope, filter, attributes, typesOnly, null);
  }



  /**
   * Processes a search in the directory server.
   *
   * @param  baseDN       The base DN for the search.
   * @param  scope        The scope for the search.
   * @param  filter       The filter for the search.
   * @param  attributes   The set of attributes to request.
   * @param  typesOnly    Indicates whether to return attribute types only or
   *                      both types and values.
   * @param  constraints  The constraints to use for the search operation.
   *
   * @return  The entry that was read.
   *
   * @throws  LDAPException  If a problem occurs while performing the search.
   */
  @NotNull()
  public LDAPSearchResults search(@NotNull final String baseDN, final int scope,
              @NotNull final String filter,
              @Nullable final String[] attributes,
              final boolean typesOnly,
              @Nullable final LDAPSearchConstraints constraints)
         throws LDAPException
  {
    final LDAPSearchResults results;
    final LDAPSearchConstraints c =
         (constraints == null) ? searchConstraints : constraints;
    results = new LDAPSearchResults(c.getTimeLimit());

    try
    {
      final SearchRequest searchRequest = new SearchRequest(results, baseDN,
           SearchScope.valueOf(scope), filter, attributes);

      searchRequest.setDerefPolicy(
           DereferencePolicy.valueOf(c.getDereference()));
      searchRequest.setSizeLimit(c.getMaxResults());
      searchRequest.setTimeLimitSeconds(c.getServerTimeLimit());
      searchRequest.setTypesOnly(typesOnly);

      update(searchRequest, constraints);

      results.setAsyncRequestID(conn.asyncSearch(searchRequest));
      return results;
    }
    catch (final com.unboundid.ldap.sdk.LDAPException le)
    {
      Debug.debugException(le);
      setResponseControls(le);
      throw new LDAPException(le);
    }
  }



  /**
   * Retrieves the set of controls to use in a request.
   *
   * @param  c  The constraints to be applied.
   *
   * @return  The set of controls to use in a request.
   */
  @NotNull()
  private Control[] getControls(@Nullable final LDAPConstraints c)
  {
    Control[] controls = null;
    if (c != null)
    {
      controls = LDAPControl.toControls(c.getServerControls());
    }
    else if (constraints != null)
    {
      controls = LDAPControl.toControls(constraints.getServerControls());
    }

    if (controls == null)
    {
      return new Control[0];
    }
    else
    {
      return controls;
    }
  }



  /**
   * Updates the provided request to account for the given set of constraints.
   *
   * @param  request      The request to be updated.
   * @param  constraints  The constraints to be applied.
   */
  private void update(@NotNull final UpdatableLDAPRequest request,
                      @Nullable final LDAPConstraints constraints)
  {
    final LDAPConstraints c =
         (constraints == null) ? this.constraints : constraints;

    request.setControls(LDAPControl.toControls(c.getServerControls()));
    request.setResponseTimeoutMillis(c.getTimeLimit());
    request.setFollowReferrals(c.getReferrals());
  }



  /**
   * Sets the response controls for this connection.
   *
   * @param  ldapResult  The result containing the controls to use.
   */
  private void setResponseControls(@NotNull final LDAPResult ldapResult)
  {
    if (ldapResult.hasResponseControl())
    {
      responseControls =
           LDAPControl.toLDAPControls(ldapResult.getResponseControls());
    }
    else
    {
      responseControls = null;
    }
  }



  /**
   * Sets the response controls for this connection.
   *
   * @param  ldapException  The exception containing the controls to use.
   */
  private void setResponseControls(
       @NotNull final com.unboundid.ldap.sdk.LDAPException ldapException)
  {
    if (ldapException.hasResponseControl())
    {
      responseControls =
           LDAPControl.toLDAPControls(ldapException.getResponseControls());
    }
    else
    {
      responseControls = null;
    }
  }
}
