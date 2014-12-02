/*
 * Copyright 2007-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2014 UnboundID Corp.
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
package com.unboundid.ldap.sdk;



import java.net.InetAddress;
import java.net.Socket;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.sasl.SaslClient;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.AbandonRequestProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.ldap.protocol.UnbindRequestProtocolOp;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.DebugType;
import com.unboundid.util.SynchronizedSocketFactory;
import com.unboundid.util.SynchronizedSSLSocketFactory;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.WeakHashSet;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides a facility for interacting with an LDAPv3 directory
 * server.  It provides a means of establishing a connection to the server,
 * sending requests, and reading responses.  See
 * <A HREF="http://www.ietf.org/rfc/rfc4511.txt">RFC 4511</A> for the LDAPv3
 * protocol specification and more information about the types of operations
 * defined in LDAP.
 * <BR><BR>
 * <H2>Creating, Establishing, and Authenticating Connections</H2>
 * An LDAP connection can be established either at the time that the object is
 * created or as a separate step.  Similarly, authentication can be performed on
 * the connection at the time it is created, at the time it is established, or
 * as a separate process.  For example:
 * <BR><BR>
 * <PRE>
 *   // Create a new, unestablished connection.  Then connect and perform a
 *   // simple bind as separate operations.
 *   LDAPConnection c = new LDAPConnection();
 *   c.connect(address, port);
 *   BindResult bindResult = c.bind(bindDN, password);
 *
 *   // Create a new connection that is established at creation time, and then
 *   // authenticate separately using simple authentication.
 *   LDAPConnection c = new LDAPConnection(address, port);
 *   BindResult bindResult = c.bind(bindDN, password);
 *
 *   // Create a new connection that is established and bound using simple
 *   // authentication all in one step.
 *   LDAPConnection c = new LDAPConnection(address, port, bindDN, password);
 * </PRE>
 * <BR><BR>
 * When authentication is performed at the time that the connection is
 * established, it is only possible to perform a simple bind and it is not
 * possible to include controls in the bind request, nor is it possible to
 * receive response controls if the bind was successful.  Therefore, it is
 * recommended that authentication be performed as a separate step if the server
 * may return response controls even in the event of a successful authentication
 * (e.g., a control that may indicate that the user's password will soon
 * expire).  See the {@link BindRequest} class for more information about
 * authentication in the UnboundID LDAP SDK for Java.
 * <BR><BR>
 * By default, connections will use standard unencrypted network sockets.
 * However, it may be desirable to create connections that use SSL/TLS to
 * encrypt communication.  This can be done by specifying a
 * {@link javax.net.SocketFactory} that should be used to create the socket to
 * use to communicate with the directory server.  The
 * {@link javax.net.ssl.SSLSocketFactory#getDefault} method or the
 * {@link javax.net.ssl.SSLContext#getSocketFactory} method may be used to
 * obtain a socket factory for performing SSL communication.  See the
 * <A HREF=
 * "http://java.sun.com/j2se/1.5.0/docs/guide/security/jsse/JSSERefGuide.html">
 * JSSE Reference Guide</A> for more information on using these classes.
 * Alternately, you may use the {@link com.unboundid.util.ssl.SSLUtil} class to
 * simplify the process.
 * <BR><BR>
 * Whenever the connection is no longer needed, it may be terminated using the
 * {@link LDAPConnection#close} method.
 * <BR><BR>
 * <H2>Processing LDAP Operations</H2>
 * This class provides a number of methods for processing the different types of
 * operations.  The types of operations that can be processed include:
 * <UL>
 *   <LI>Abandon -- This may be used to request that the server stop processing
 *      on an operation that has been invoked asynchronously.</LI>
 *   <LI>Add -- This may be used to add a new entry to the directory
 *       server.  See the {@link AddRequest} class for more information about
 *       processing add operations.</LI>
 *   <LI>Bind -- This may be used to authenticate to the directory server.  See
 *       the {@link BindRequest} class for more information about processing
 *       bind operations.</LI>
 *   <LI>Compare -- This may be used to determine whether a specified entry has
 *       a given attribute value.  See the {@link CompareRequest} class for more
 *       information about processing compare operations.</LI>
 *   <LI>Delete -- This may be used to remove an entry from the directory
 *       server.  See the {@link DeleteRequest} class for more information about
 *       processing delete operations.</LI>
 *   <LI>Extended -- This may be used to process an operation which is not
 *       part of the core LDAP protocol but is a custom extension supported by
 *       the directory server.  See the {@link ExtendedRequest} class for more
 *       information about processing extended operations.</LI>
 *   <LI>Modify -- This may be used to alter an entry in the directory
 *       server.  See the {@link ModifyRequest} class for more information about
 *       processing modify operations.</LI>
 *   <LI>Modify DN -- This may be used to rename an entry or subtree and/or move
 *       that entry or subtree below a new parent in the directory server.  See
 *       the {@link ModifyDNRequest} class for more information about processing
 *       modify DN operations.</LI>
 *   <LI>Search -- This may be used to retrieve a set of entries in the server
 *       that match a given set of criteria.  See the {@link SearchRequest}
 *       class for more information about processing search operations.</LI>
 * </UL>
 * <BR><BR>
 * Most of the methods in this class used to process operations operate in a
 * synchronous manner.  In these cases, the SDK will send a request to the
 * server and wait for a response to arrive before returning to the caller.  In
 * these cases, the value returned will include the contents of that response,
 * including the result code, diagnostic message, matched DN, referral URLs, and
 * any controls that may have been included.  However, it also possible to
 * process operations asynchronously, in which case the SDK will return control
 * back to the caller after the request has been sent to the server but before
 * the response has been received.  In this case, the SDK will return an
 * {@link AsyncRequestID} object which may be used to later abandon or cancel
 * that operation if necessary, and will notify the client when the response
 * arrives via a listener interface.
 * <BR><BR>
 * This class is mostly threadsafe.  It is possible to process multiple
 * concurrent operations over the same connection as long as the methods being
 * invoked will not change the state of the connection in a way that might
 * impact other operations in progress in unexpected ways.  In particular, the
 * following should not be attempted while any other operations may be in
 * progress on this connection:
 * <UL>
 *   <LI>
 *     Using one of the {@code connect} methods to re-establish the connection.
 *   </LI>
 *   <LI>
 *     Using one of the {@code close} methods to terminate the connection.
 *   </LI>
 *   <LI>
 *     Using one of the {@code bind} methods to attempt to authenticate the
 *     connection (unless you are certain that the bind will not impact the
 *     identity of the associated connection, for example by including the
 *     retain identity request control in the bind request if using the
 *     Commercial Edition of the LDAP SDK in conjunction with an UnboundID
 *     Directory Server).
 *   </LI>
 *   <LI>
 *     Attempting to make a change to the way that the underlying communication
 *     is processed (e.g., by using the StartTLS extended operation to convert
 *     an insecure connection into a secure one).
 *   </LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_THREADSAFE)
public final class LDAPConnection
       implements LDAPInterface, ReferralConnector
{
  /**
   * The counter that will be used when assigning connection IDs to connections.
   */
  private static final AtomicLong NEXT_CONNECTION_ID = new AtomicLong(0L);



  /**
   * The default socket factory that will be used if no alternate factory is
   * provided.
   */
  private static final SocketFactory DEFAULT_SOCKET_FACTORY =
                                          SocketFactory.getDefault();



  /**
   * A set of weak references to schema objects that can be shared across
   * connections if they are identical.
   */
  private static final WeakHashSet<Schema> SCHEMA_SET =
       new WeakHashSet<Schema>();



  // The connection pool with which this connection is associated, if
  // applicable.
  private AbstractConnectionPool connectionPool;

  // Indicates whether to perform a reconnect before the next write.
  private final AtomicBoolean needsReconnect;

  // The disconnect information for this connection.
  private final AtomicReference<DisconnectInfo> disconnectInfo;

  // The last successful bind request processed on this connection.
  private volatile BindRequest lastBindRequest;

  // Indicates whether a request has been made to close this connection.
  private volatile boolean closeRequested;

  // Indicates whether an unbind request has been sent over this connection.
  private volatile boolean unbindRequestSent;

  // The extended request used to initiate StartTLS on this connection.
  private volatile ExtendedRequest startTLSRequest;

  // The port of the server to which a connection should be re-established.
  private int reconnectPort = -1;

  // The connection internals used to actually perform the network
  // communication.
  private volatile LDAPConnectionInternals connectionInternals;

  // The set of connection options for this connection.
  private LDAPConnectionOptions connectionOptions;

  // The set of statistics for this connection.
  private final LDAPConnectionStatistics connectionStatistics;

  // The unique identifier assigned to this connection when it was created.  It
  // will not change over the life of the connection, even if the connection is
  // closed and re-established (or even re-established to a different server).
  private final long connectionID;

  // The time of the last rebind attempt.
  private long lastReconnectTime;

  // The most recent time that an LDAP message was sent or received on this
  // connection.
  private volatile long lastCommunicationTime;

  // A map in which arbitrary attachments may be stored or managed.
  private Map<String,Object> attachments;

  // The referral connector that will be used to establish connections to remote
  // servers when following a referral.
  private volatile ReferralConnector referralConnector;

  // The cached schema read from the server.
  private volatile Schema cachedSchema;

  // The socket factory used for the last connection attempt.
  private SocketFactory lastUsedSocketFactory;

  // The socket factory used to create sockets for subsequent connection
  // attempts.
  private volatile SocketFactory socketFactory;

  // A stack trace of the thread that last established this connection.
  private StackTraceElement[] connectStackTrace;

  // The user-friendly name assigned to this connection.
  private String connectionName;

  // The user-friendly name assigned to the connection pool with which this
  // connection is associated.
  private String connectionPoolName;

  // A string representation of the host and port to which the last connection
  // attempt (whether successful or not, and whether it is still established)
  // was made.
  private String hostPort;

  // The address of the server to which a connection should be re-established.
  private String reconnectAddress;

  // A timer that may be used to enforce timeouts for asynchronous operations.
  private Timer timer;



  /**
   * Creates a new LDAP connection using the default socket factory and default
   * set of connection options.  No actual network connection will be
   * established.
   */
  public LDAPConnection()
  {
    this(null, null);
  }



  /**
   * Creates a new LDAP connection using the default socket factory and provided
   * set of connection options.  No actual network connection will be
   * established.
   *
   * @param  connectionOptions  The set of connection options to use for this
   *                            connection.  If it is {@code null}, then a
   *                            default set of options will be used.
   */
  public LDAPConnection(final LDAPConnectionOptions connectionOptions)
  {
    this(null, connectionOptions);
  }



  /**
   * Creates a new LDAP connection using the specified socket factory.  No
   * actual network connection will be established.
   *
   * @param  socketFactory  The socket factory to use when establishing
   *                        connections.  If it is {@code null}, then a default
   *                        socket factory will be used.
   */
  public LDAPConnection(final SocketFactory socketFactory)
  {
    this(socketFactory, null);
  }



  /**
   * Creates a new LDAP connection using the specified socket factory.  No
   * actual network connection will be established.
   *
   * @param  socketFactory      The socket factory to use when establishing
   *                            connections.  If it is {@code null}, then a
   *                            default socket factory will be used.
   * @param  connectionOptions  The set of connection options to use for this
   *                            connection.  If it is {@code null}, then a
   *                            default set of options will be used.
   */
  public LDAPConnection(final SocketFactory socketFactory,
                        final LDAPConnectionOptions connectionOptions)
  {
    needsReconnect = new AtomicBoolean(false);
    disconnectInfo = new AtomicReference<DisconnectInfo>();
    lastCommunicationTime = -1L;

    connectionID = NEXT_CONNECTION_ID.getAndIncrement();

    if (connectionOptions == null)
    {
      this.connectionOptions = new LDAPConnectionOptions();
    }
    else
    {
      this.connectionOptions = connectionOptions.duplicate();
    }

    final SocketFactory f;
    if (socketFactory == null)
    {
      f = DEFAULT_SOCKET_FACTORY;
    }
    else
    {
      f = socketFactory;
    }

    if (this.connectionOptions.allowConcurrentSocketFactoryUse())
    {
      this.socketFactory = f;
    }
    else
    {
      if (f instanceof SSLSocketFactory)
      {
        this.socketFactory =
             new SynchronizedSSLSocketFactory((SSLSocketFactory) f);
      }
      else
      {
        this.socketFactory = new SynchronizedSocketFactory(f);
      }
    }

    attachments          = null;
    connectionStatistics = new LDAPConnectionStatistics();
    connectionName       = null;
    connectionPoolName   = null;
    cachedSchema         = null;
    timer                = null;

    referralConnector = this.connectionOptions.getReferralConnector();
    if (referralConnector == null)
    {
      referralConnector = this;
    }
  }



  /**
   * Creates a new, unauthenticated LDAP connection that is established to the
   * specified server.
   *
   * @param  host  The string representation of the address of the server to
   *               which the connection should be established.  It may be a
   *               resolvable name or an IP address.  It must not be
   *               {@code null}.
   * @param  port  The port number of the server to which the connection should
   *               be established.  It should be a value between 1 and 65535,
   *               inclusive.
   *
   * @throws  LDAPException  If a problem occurs while attempting to connect to
   *                         the specified server.
   */
  public LDAPConnection(final String host, final int port)
         throws LDAPException
  {
    this(null, null, host, port);
  }



  /**
   * Creates a new, unauthenticated LDAP connection that is established to the
   * specified server.
   *
   * @param  connectionOptions  The set of connection options to use for this
   *                            connection.  If it is {@code null}, then a
   *                            default set of options will be used.
   * @param  host               The string representation of the address of the
   *                            server to which the connection should be
   *                            established.  It may be a resolvable name or an
   *                            IP address.  It must not be {@code null}.
   * @param  port               The port number of the server to which the
   *                            connection should be established.  It should be
   *                            a value between 1 and 65535, inclusive.
   *
   * @throws  LDAPException  If a problem occurs while attempting to connect to
   *                         the specified server.
   */
  public LDAPConnection(final LDAPConnectionOptions connectionOptions,
                        final String host, final int port)
         throws LDAPException
  {
    this(null, connectionOptions, host, port);
  }



  /**
   * Creates a new, unauthenticated LDAP connection that is established to the
   * specified server.
   *
   * @param  socketFactory  The socket factory to use when establishing
   *                        connections.  If it is {@code null}, then a default
   *                        socket factory will be used.
   * @param  host           The string representation of the address of the
   *                        server to which the connection should be
   *                        established.  It may be a resolvable name or an IP
   *                        address.  It must not be {@code null}.
   * @param  port           The port number of the server to which the
   *                        connection should be established.  It should be a
   *                        value between 1 and 65535, inclusive.
   *
   * @throws  LDAPException  If a problem occurs while attempting to connect to
   *                         the specified server.
   */
  public LDAPConnection(final SocketFactory socketFactory, final String host,
                        final int port)
         throws LDAPException
  {
    this(socketFactory, null, host, port);
  }



  /**
   * Creates a new, unauthenticated LDAP connection that is established to the
   * specified server.
   *
   * @param  socketFactory      The socket factory to use when establishing
   *                            connections.  If it is {@code null}, then a
   *                            default socket factory will be used.
   * @param  connectionOptions  The set of connection options to use for this
   *                            connection.  If it is {@code null}, then a
   *                            default set of options will be used.
   * @param  host               The string representation of the address of the
   *                            server to which the connection should be
   *                            established.  It may be a resolvable name or an
   *                            IP address.  It must not be {@code null}.
   * @param  port               The port number of the server to which the
   *                            connection should be established.  It should be
   *                            a value between 1 and 65535, inclusive.
   *
   * @throws  LDAPException  If a problem occurs while attempting to connect to
   *                         the specified server.
   */
  public LDAPConnection(final SocketFactory socketFactory,
                        final LDAPConnectionOptions connectionOptions,
                        final String host, final int port)
         throws LDAPException
  {
    this(socketFactory, connectionOptions);

    connect(host, port);
  }



  /**
   * Creates a new LDAP connection that is established to the specified server
   * and is authenticated as the specified user (via LDAP simple
   * authentication).
   *
   * @param  host          The string representation of the address of the
   *                       server to which the connection should be established.
   *                       It may be a resolvable name or an IP address.  It
   *                       must not be {@code null}.
   * @param  port          The port number of the server to which the
   *                       connection should be established.  It should be a
   *                       value between 1 and 65535, inclusive.
   * @param  bindDN        The DN to use to authenticate to the directory
   *                       server.
   * @param  bindPassword  The password to use to authenticate to the directory
   *                       server.
   *
   * @throws  LDAPException  If a problem occurs while attempting to connect to
   *                         the specified server.
   */
  public LDAPConnection(final String host, final int port, final String bindDN,
                        final String bindPassword)
         throws LDAPException
  {
    this(null, null, host, port, bindDN, bindPassword);
  }



  /**
   * Creates a new LDAP connection that is established to the specified server
   * and is authenticated as the specified user (via LDAP simple
   * authentication).
   *
   * @param  connectionOptions  The set of connection options to use for this
   *                            connection.  If it is {@code null}, then a
   *                            default set of options will be used.
   * @param  host               The string representation of the address of the
   *                            server to which the connection should be
   *                            established.  It may be a resolvable name or an
   *                            IP address.  It must not be {@code null}.
   * @param  port               The port number of the server to which the
   *                            connection should be established.  It should be
   *                            a value between 1 and 65535, inclusive.
   * @param  bindDN             The DN to use to authenticate to the directory
   *                            server.
   * @param  bindPassword       The password to use to authenticate to the
   *                            directory server.
   *
   * @throws  LDAPException  If a problem occurs while attempting to connect to
   *                         the specified server.
   */
  public LDAPConnection(final LDAPConnectionOptions connectionOptions,
                        final String host, final int port, final String bindDN,
                        final String bindPassword)
         throws LDAPException
  {
    this(null, connectionOptions, host, port, bindDN, bindPassword);
  }



  /**
   * Creates a new LDAP connection that is established to the specified server
   * and is authenticated as the specified user (via LDAP simple
   * authentication).
   *
   * @param  socketFactory  The socket factory to use when establishing
   *                        connections.  If it is {@code null}, then a default
   *                        socket factory will be used.
   * @param  host           The string representation of the address of the
   *                        server to which the connection should be
   *                        established.  It may be a resolvable name or an IP
   *                        address.  It must not be {@code null}.
   * @param  port           The port number of the server to which the
   *                        connection should be established.  It should be a
   *                        value between 1 and 65535, inclusive.
   * @param  bindDN         The DN to use to authenticate to the directory
   *                        server.
   * @param  bindPassword   The password to use to authenticate to the directory
   *                        server.
   *
   * @throws  LDAPException  If a problem occurs while attempting to connect to
   *                         the specified server.
   */
  public LDAPConnection(final SocketFactory socketFactory, final String host,
                        final int port, final String bindDN,
                        final String bindPassword)
         throws LDAPException
  {
    this(socketFactory, null, host, port, bindDN, bindPassword);
  }



  /**
   * Creates a new LDAP connection that is established to the specified server
   * and is authenticated as the specified user (via LDAP simple
   * authentication).
   *
   * @param  socketFactory      The socket factory to use when establishing
   *                            connections.  If it is {@code null}, then a
   *                            default socket factory will be used.
   * @param  connectionOptions  The set of connection options to use for this
   *                            connection.  If it is {@code null}, then a
   *                            default set of options will be used.
   * @param  host               The string representation of the address of the
   *                            server to which the connection should be
   *                            established.  It may be a resolvable name or an
   *                            IP address.  It must not be {@code null}.
   * @param  port               The port number of the server to which the
   *                            connection should be established.  It should be
   *                            a value between 1 and 65535, inclusive.
   * @param  bindDN             The DN to use to authenticate to the directory
   *                            server.
   * @param  bindPassword       The password to use to authenticate to the
   *                            directory server.
   *
   * @throws  LDAPException  If a problem occurs while attempting to connect to
   *                         the specified server.
   */
  public LDAPConnection(final SocketFactory socketFactory,
                        final LDAPConnectionOptions connectionOptions,
                        final String host, final int port, final String bindDN,
                        final String bindPassword)
         throws LDAPException
  {
    this(socketFactory, connectionOptions, host, port);

    try
    {
      bind(new SimpleBindRequest(bindDN, bindPassword));
    }
    catch (LDAPException le)
    {
      debugException(le);
      setDisconnectInfo(DisconnectType.BIND_FAILED, null, le);
      close();
      throw le;
    }
  }



  /**
   * Establishes an unauthenticated connection to the directory server using the
   * provided information.  If the connection is already established, then it
   * will be closed and re-established.
   * <BR><BR>
   * If this method is invoked while any operations are in progress on this
   * connection, then the directory server may or may not abort processing for
   * those operations, depending on the type of operation and how far along the
   * server has already gotten while processing that operation.  It is
   * recommended that all active operations be abandoned, canceled, or allowed
   * to complete before attempting to re-establish an active connection.
   *
   * @param  host  The string representation of the address of the server to
   *               which the connection should be established.  It may be a
   *               resolvable name or an IP address.  It must not be
   *               {@code null}.
   * @param  port  The port number of the server to which the connection should
   *               be established.  It should be a value between 1 and 65535,
   *               inclusive.
   *
   * @throws  LDAPException  If an error occurs while attempting to establish
   *                         the connection.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public void connect(final String host, final int port)
         throws LDAPException
  {
    connect(host, port, connectionOptions.getConnectTimeoutMillis());
  }



  /**
   * Establishes an unauthenticated connection to the directory server using the
   * provided information.  If the connection is already established, then it
   * will be closed and re-established.
   * <BR><BR>
   * If this method is invoked while any operations are in progress on this
   * connection, then the directory server may or may not abort processing for
   * those operations, depending on the type of operation and how far along the
   * server has already gotten while processing that operation.  It is
   * recommended that all active operations be abandoned, canceled, or allowed
   * to complete before attempting to re-establish an active connection.
   *
   * @param  host     The string representation of the address of the server to
   *                  which the connection should be established.  It may be a
   *                  resolvable name or an IP address.  It must not be
   *                  {@code null}.
   * @param  port     The port number of the server to which the connection
   *                  should be established.  It should be a value between 1 and
   *                  65535, inclusive.
   * @param  timeout  The maximum length of time in milliseconds to wait for the
   *                  connection to be established before failing, or zero to
   *                  indicate that no timeout should be enforced (although if
   *                  the attempt stalls long enough, then the underlying
   *                  operating system may cause it to timeout).
   *
   * @throws  LDAPException  If an error occurs while attempting to establish
   *                         the connection.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public void connect(final String host, final int port, final int timeout)
         throws LDAPException
  {
    final InetAddress inetAddress;
    try
    {
      inetAddress = InetAddress.getByName(host);
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_CONN_RESOLVE_ERROR.get(host, getExceptionMessage(e)),
           e);
    }

    connect(host, inetAddress, port, timeout);
  }



  /**
   * Establishes an unauthenticated connection to the directory server using the
   * provided information.  If the connection is already established, then it
   * will be closed and re-established.
   * <BR><BR>
   * If this method is invoked while any operations are in progress on this
   * connection, then the directory server may or may not abort processing for
   * those operations, depending on the type of operation and how far along the
   * server has already gotten while processing that operation.  It is
   * recommended that all active operations be abandoned, canceled, or allowed
   * to complete before attempting to re-establish an active connection.
   *
   * @param  inetAddress  The inet address of the server to which the connection
   *                      should be established.  It must not be {@code null}.
   * @param  port         The port number of the server to which the connection
   *                      should be established.  It should be a value between 1
   *                      and 65535, inclusive.
   * @param  timeout      The maximum length of time in milliseconds to wait for
   *                      the connection to be established before failing, or
   *                      zero to indicate that no timeout should be enforced
   *                      (although if the attempt stalls long enough, then the
   *                      underlying operating system may cause it to timeout).
   *
   * @throws  LDAPException  If an error occurs while attempting to establish
   *                         the connection.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public void connect(final InetAddress inetAddress, final int port,
                      final int timeout)
         throws LDAPException
  {
    connect(inetAddress.getHostName(), inetAddress, port, timeout);
  }



  /**
   * Establishes an unauthenticated connection to the directory server using the
   * provided information.  If the connection is already established, then it
   * will be closed and re-established.
   * <BR><BR>
   * If this method is invoked while any operations are in progress on this
   * connection, then the directory server may or may not abort processing for
   * those operations, depending on the type of operation and how far along the
   * server has already gotten while processing that operation.  It is
   * recommended that all active operations be abandoned, canceled, or allowed
   * to complete before attempting to re-establish an active connection.
   *
   * @param  host         The string representation of the address of the server
   *                      to which the connection should be established.  It may
   *                      be a resolvable name or an IP address.  It must not be
   *                      {@code null}.
   * @param  inetAddress  The inet address of the server to which the connection
   *                      should be established.  It must not be {@code null}.
   * @param  port         The port number of the server to which the connection
   *                      should be established.  It should be a value between 1
   *                      and 65535, inclusive.
   * @param  timeout      The maximum length of time in milliseconds to wait for
   *                      the connection to be established before failing, or
   *                      zero to indicate that no timeout should be enforced
   *                      (although if the attempt stalls long enough, then the
   *                      underlying operating system may cause it to timeout).
   *
   * @throws  LDAPException  If an error occurs while attempting to establish
   *                         the connection.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public void connect(final String host, final InetAddress inetAddress,
                      final int port, final int timeout)
         throws LDAPException
  {
    ensureNotNull(host, inetAddress, port);

    needsReconnect.set(false);
    hostPort = host + ':' + port;
    lastCommunicationTime = -1L;
    startTLSRequest = null;

    if (isConnected())
    {
      setDisconnectInfo(DisconnectType.RECONNECT, null, null);
      close();
    }

    lastUsedSocketFactory = socketFactory;
    reconnectAddress      = host;
    reconnectPort         = port;
    cachedSchema          = null;
    unbindRequestSent     = false;

    disconnectInfo.set(null);

    try
    {
      connectionStatistics.incrementNumConnects();
      connectionInternals = new LDAPConnectionInternals(this, connectionOptions,
           lastUsedSocketFactory, host, inetAddress, port, timeout);
      connectionInternals.startConnectionReader();
      lastCommunicationTime = System.currentTimeMillis();
    }
    catch (Exception e)
    {
      debugException(e);
      setDisconnectInfo(DisconnectType.LOCAL_ERROR, null, e);
      connectionInternals = null;
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_CONN_CONNECT_ERROR.get(getHostPort(), getExceptionMessage(e)),
           e);
    }

    if (connectionOptions.useSchema())
    {
      try
      {
        cachedSchema = getCachedSchema(this);
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }
  }



  /**
   * Attempts to re-establish a connection to the server and re-authenticate if
   * appropriate.
   *
   * @throws  LDAPException  If a problem occurs while attempting to re-connect
   *                         or re-authenticate.
   */
  public void reconnect()
         throws LDAPException
  {
    needsReconnect.set(false);
    if ((System.currentTimeMillis() - lastReconnectTime) < 1000L)
    {
      // If the last reconnect attempt was less than 1 second ago, then abort.
      throw new LDAPException(ResultCode.SERVER_DOWN,
                              ERR_CONN_MULTIPLE_FAILURES.get());
    }

    BindRequest bindRequest = null;
    if (lastBindRequest != null)
    {
      bindRequest = lastBindRequest.getRebindRequest(reconnectAddress,
                                                     reconnectPort);
      if (bindRequest == null)
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_CONN_CANNOT_REAUTHENTICATE.get(getHostPort()));
      }
    }

    final ExtendedRequest startTLSExtendedRequest = startTLSRequest;

    setDisconnectInfo(DisconnectType.RECONNECT, null, null);
    terminate(null);

    try
    {
      Thread.sleep(10);
    } catch (final Exception e) {}

    connect(reconnectAddress, reconnectPort);

    if (startTLSExtendedRequest != null)
    {
      try
      {
        final ExtendedResult startTLSResult =
             processExtendedOperation(startTLSExtendedRequest);
        if (startTLSResult.getResultCode() != ResultCode.SUCCESS)
        {
          throw new LDAPException(startTLSResult);
        }
      }
      catch (final LDAPException le)
      {
        debugException(le);
        setDisconnectInfo(DisconnectType.SECURITY_PROBLEM, null, le);
        terminate(null);

        throw le;
      }
    }

    if (bindRequest != null)
    {
      try
      {
        bind(bindRequest);
      }
      catch (final LDAPException le)
      {
        debugException(le);
        setDisconnectInfo(DisconnectType.BIND_FAILED, null, le);
        terminate(null);

        throw le;
      }
    }

    lastReconnectTime = System.currentTimeMillis();
  }



  /**
   * Sets a flag indicating that the connection should be re-established before
   * sending the next request.
   */
  void setNeedsReconnect()
  {
    needsReconnect.set(true);
  }



  /**
   * Indicates whether this connection is currently established.
   *
   * @return  {@code true} if this connection is currently established, or
   *          {@code false} if it is not.
   */
  public boolean isConnected()
  {
    final LDAPConnectionInternals internals = connectionInternals;

    if (internals == null)
    {
      return false;
    }

    if (! internals.isConnected())
    {
      setClosed();
      return false;
    }

    return (! needsReconnect.get());
  }



  /**
   * Converts this clear-text connection to one that encrypts all communication
   * using Transport Layer Security.  This method is intended for use as a
   * helper for processing in the course of the StartTLS extended operation and
   * should not be used for other purposes.
   *
   * @param  sslSocketFactory  The SSL socket factory to use to convert an
   *                           insecure connection into a secure connection.  It
   *                           must not be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while converting this
   *                         connection to use TLS.
   */
  void convertToTLS(final SSLSocketFactory sslSocketFactory)
       throws LDAPException
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
                              ERR_CONN_NOT_ESTABLISHED.get());
    }
    else
    {
      internals.convertToTLS(sslSocketFactory);
    }
  }



  /**
   * Converts this clear-text connection to one that uses SASL integrity and/or
   * confidentiality.
   *
   * @param  saslClient  The SASL client that will be used to secure the
   *                     communication.
   *
   * @throws  LDAPException  If a problem occurs while attempting to convert the
   *                         connection to use SASL QoP.
   */
  void applySASLQoP(final SaslClient saslClient)
       throws LDAPException
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_CONN_NOT_ESTABLISHED.get());
    }
    else
    {
      internals.applySASLQoP(saslClient);
    }
  }



  /**
   * Retrieves the set of connection options for this connection.  Changes to
   * the object that is returned will directly impact this connection.
   *
   * @return  The set of connection options for this connection.
   */
  public LDAPConnectionOptions getConnectionOptions()
  {
    return connectionOptions;
  }



  /**
   * Specifies the set of connection options for this connection.  Some changes
   * may not take effect for operations already in progress, and some changes
   * may not take effect for a connection that is already established.
   *
   * @param  connectionOptions  The set of connection options for this
   *                            connection.  It may be {@code null} if a default
   *                            set of options is to be used.
   */
  public void setConnectionOptions(
                   final LDAPConnectionOptions connectionOptions)
  {
    if (connectionOptions == null)
    {
      this.connectionOptions = new LDAPConnectionOptions();
    }
    else
    {
      final LDAPConnectionOptions newOptions = connectionOptions.duplicate();
      if (debugEnabled(DebugType.LDAP) && newOptions.useSynchronousMode() &&
          (! connectionOptions.useSynchronousMode()) && isConnected())
      {
        debug(Level.WARNING, DebugType.LDAP,
              "A call to LDAPConnection.setConnectionOptions() with " +
              "useSynchronousMode=true will have no effect for this " +
              "connection because it is already established.  The " +
              "useSynchronousMode option must be set before the connection " +
              "is established to have any effect.");
      }

      this.connectionOptions = newOptions;
    }

    final ReferralConnector rc = this.connectionOptions.getReferralConnector();
    if (rc == null)
    {
      referralConnector = this;
    }
    else
    {
      referralConnector = rc;
    }
  }



  /**
   * Retrieves the socket factory that was used when creating the socket for the
   * last connection attempt (whether successful or unsuccessful) for this LDAP
   * connection.
   *
   * @return  The socket factory that was used when creating the socket for the
   *          last connection attempt for this LDAP connection, or {@code null}
   *          if no attempt has yet been made to establish this connection.
   */
  public SocketFactory getLastUsedSocketFactory()
  {
    return lastUsedSocketFactory;
  }



  /**
   * Retrieves the socket factory to use to create the socket for subsequent
   * connection attempts.  This may or may not be the socket factory that was
   * used to create the current established connection.
   *
   * @return  The socket factory to use to create the socket for subsequent
   *          connection attempts.
   */
  public SocketFactory getSocketFactory()
  {
    return socketFactory;
  }



  /**
   * Specifies the socket factory to use to create the socket for subsequent
   * connection attempts.  This will not impact any established connection.
   *
   * @param  socketFactory  The socket factory to use to create the socket for
   *                        subsequent connection attempts.
   */
  public void setSocketFactory(final SocketFactory socketFactory)
  {
    if (socketFactory == null)
    {
      this.socketFactory = DEFAULT_SOCKET_FACTORY;
    }
    else
    {
      this.socketFactory = socketFactory;
    }
  }



  /**
   * Retrieves the {@code SSLSession} currently being used to secure
   * communication on this connection.  This may be available for connections
   * that were secured at the time they were created (via an
   * {@code SSLSocketFactory}), or for connections secured after their creation
   * (via the StartTLS extended operation).  This will not be available for
   * unencrypted connections, or connections secured in other ways (e.g., via
   * SASL QoP).
   *
   * @return  The {@code SSLSession} currently being used to secure
   *          communication on this connection, or {@code null} if no
   *          {@code SSLSession} is available.
   */
  public SSLSession getSSLSession()
  {
    final LDAPConnectionInternals internals = connectionInternals;

    if (internals == null)
    {
      return null;
    }

    final Socket socket = internals.getSocket();
    if ((socket != null) && (socket instanceof SSLSocket))
    {
      final SSLSocket sslSocket = (SSLSocket) socket;
      return sslSocket.getSession();
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves a value that uniquely identifies this connection within the JVM
   * Each {@code LDAPConnection} object will be assigned a different connection
   * ID, and that connection ID will not change over the life of the object,
   * even if the connection is closed and re-established (whether re-established
   * to the same server or a different server).
   *
   * @return  A value that uniquely identifies this connection within the JVM.
   */
  public long getConnectionID()
  {
    return connectionID;
  }



  /**
   * Retrieves the user-friendly name that has been assigned to this connection.
   *
   * @return  The user-friendly name that has been assigned to this connection,
   *          or {@code null} if none has been assigned.
   */
  public String getConnectionName()
  {
    return connectionName;
  }



  /**
   * Specifies the user-friendly name that should be used for this connection.
   * This name may be used in debugging to help identify the purpose of this
   * connection.  This will have no effect for connections which are part of a
   * connection pool.
   *
   * @param  connectionName  The user-friendly name that should be used for this
   *                         connection.
   */
  public void setConnectionName(final String connectionName)
  {
    if (connectionPool == null)
    {
      this.connectionName = connectionName;
      if (connectionInternals != null)
      {
        final LDAPConnectionReader reader =
             connectionInternals.getConnectionReader();
        reader.updateThreadName();
      }
    }
  }



  /**
   * Retrieves the connection pool with which this connection is associated, if
   * any.
   *
   * @return  The connection pool with which this connection is associated, or
   *          {@code null} if it is not associated with any connection pool.
   */
  public AbstractConnectionPool getConnectionPool()
  {
    return connectionPool;
  }



  /**
   * Retrieves the user-friendly name that has been assigned to the connection
   * pool with which this connection is associated.
   *
   * @return  The user-friendly name that has been assigned to the connection
   *          pool with which this connection is associated, or {@code null} if
   *          none has been assigned or this connection is not associated with a
   *          connection pool.
   */
  public String getConnectionPoolName()
  {
    return connectionPoolName;
  }



  /**
   * Specifies the user-friendly name that should be used for the connection
   * pool with which this connection is associated.
   *
   * @param  connectionPoolName  The user-friendly name that should be used for
   *                             the connection pool with which this connection
   *                             is associated.
   */
  void setConnectionPoolName(final String connectionPoolName)
  {
    this.connectionPoolName = connectionPoolName;
    if (connectionInternals != null)
    {
      final LDAPConnectionReader reader =
           connectionInternals.getConnectionReader();
      reader.updateThreadName();
    }
  }



  /**
   * Retrieves a string representation of the host and port for the server to
   * to which the last connection attempt was made.  It does not matter whether
   * the connection attempt was successful, nor does it matter whether it is
   * still established.  This is intended for internal use in error messages.
   *
   * @return  A string representation of the host and port for the server to
   *          which the last connection attempt was made, or an empty string if
   *          no connection attempt has yet been made on this connection.
   */
  String getHostPort()
  {
    if (hostPort == null)
    {
      return "";
    }
    else
    {
      return hostPort;
    }
  }



  /**
   * Retrieves the address of the directory server to which this connection is
   * currently established.
   *
   * @return  The address of the directory server to which this connection is
   *          currently established, or {@code null} if the connection is not
   *          established.
   */
  public String getConnectedAddress()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      return null;
    }
    else
    {
      return internals.getHost();
    }
  }



  /**
   * Retrieves the string representation of the IP address to which this
   * connection is currently established.
   *
   * @return  The string representation of the IP address to which this
   *          connection is currently established, or {@code null} if the
   *          connection is not established.
   */
  public String getConnectedIPAddress()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      return null;
    }
    else
    {
      return internals.getInetAddress().getHostAddress();
    }
  }



  /**
   * Retrieves an {@code InetAddress} object that represents the address of the
   * server to which this  connection is currently established.
   *
   * @return  An {@code InetAddress} that represents the address of the server
   *          to which this connection is currently established, or {@code null}
   *          if the connection is not established.
   */
  public InetAddress getConnectedInetAddress()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      return null;
    }
    else
    {
      return internals.getInetAddress();
    }
  }



  /**
   * Retrieves the port of the directory server to which this connection is
   * currently established.
   *
   * @return  The port of the directory server to which this connection is
   *          currently established, or -1 if the connection is not established.
   */
  public int getConnectedPort()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      return -1;
    }
    else
    {
      return internals.getPort();
    }
  }



  /**
   * Retrieves a stack trace of the thread that last attempted to establish this
   * connection.  Note that this will only be available if an attempt has been
   * made to establish this connection and the
   * {@link LDAPConnectionOptions#captureConnectStackTrace()} method for the
   * associated connection options returns {@code true}.
   *
   * @return  A stack trace of the thread that last attempted to establish this
   *          connection, or {@code null} connect stack traces are not enabled,
   *          or if no attempt has been made to establish this connection.
   */
  public StackTraceElement[] getConnectStackTrace()
  {
    return connectStackTrace;
  }



  /**
   * Provides a stack trace for the thread that last attempted to establish this
   * connection.
   *
   * @param  connectStackTrace  A stack trace for the thread that last attempted
   *                            to establish this connection.
   */
  void setConnectStackTrace(final StackTraceElement[] connectStackTrace)
  {
    this.connectStackTrace = connectStackTrace;
  }



  /**
   * Unbinds from the server and closes the connection.
   * <BR><BR>
   * If this method is invoked while any operations are in progress on this
   * connection, then the directory server may or may not abort processing for
   * those operations, depending on the type of operation and how far along the
   * server has already gotten while processing that operation.  It is
   * recommended that all active operations be abandoned, canceled, or allowed
   * to complete before attempting to close an active connection.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public void close()
  {
    closeRequested = true;
    setDisconnectInfo(DisconnectType.UNBIND, null, null);

    if (connectionPool == null)
    {
      terminate(null);
    }
    else
    {
      connectionPool.releaseDefunctConnection(this);
    }
  }



  /**
   * Unbinds from the server and closes the connection, optionally including
   * the provided set of controls in the unbind request.
   * <BR><BR>
   * If this method is invoked while any operations are in progress on this
   * connection, then the directory server may or may not abort processing for
   * those operations, depending on the type of operation and how far along the
   * server has already gotten while processing that operation.  It is
   * recommended that all active operations be abandoned, canceled, or allowed
   * to complete before attempting to close an active connection.
   *
   * @param  controls  The set of controls to include in the unbind request.  It
   *                   may be {@code null} if there are not to be any controls
   *                   sent in the unbind request.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public void close(final Control[] controls)
  {
    closeRequested = true;
    setDisconnectInfo(DisconnectType.UNBIND, null, null);

    if (connectionPool == null)
    {
      terminate(controls);
    }
    else
    {
      connectionPool.releaseDefunctConnection(this);
    }
  }



  /**
   * Unbinds from the server and closes the connection, optionally including the
   * provided set of controls in the unbind request.  This method is only
   * intended for internal use, since it does not make any attempt to release
   * the connection back to its associated connection pool, if there is one.
   *
   * @param  controls  The set of controls to include in the unbind request.  It
   *                   may be {@code null} if there are not to be any controls
   *                   sent in the unbind request.
   */
  void terminate(final Control[] controls)
  {
    if (isConnected() && (! unbindRequestSent))
    {
      try
      {
        unbindRequestSent = true;
        setDisconnectInfo(DisconnectType.UNBIND, null, null);
        if (debugEnabled(DebugType.LDAP))
        {
          debug(Level.INFO, DebugType.LDAP, "Sending LDAP unbind request.");
        }

        connectionStatistics.incrementNumUnbindRequests();
        sendMessage(new LDAPMessage(nextMessageID(),
             new UnbindRequestProtocolOp(), controls));
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }

    setClosed();
  }



  /**
   * Indicates whether a request has been made to close this connection.
   *
   * @return  {@code true} if a request has been made to close this connection,
   *          or {@code false} if not.
   */
  boolean closeRequested()
  {
    return closeRequested;
  }



  /**
   * Indicates whether an unbind request has been sent over this connection.
   *
   * @return  {@code true} if an unbind request has been sent over this
   *          connection, or {@code false} if not.
   */
  boolean unbindRequestSent()
  {
    return unbindRequestSent;
  }



  /**
   * Indicates that this LDAP connection is part of the specified
   * connection pool.
   *
   * @param  connectionPool  The connection pool with which this LDAP connection
   *                         is associated.
   */
  void setConnectionPool(final AbstractConnectionPool connectionPool)
  {
    this.connectionPool = connectionPool;
  }



  /**
   * Retrieves the directory server root DSE, which provides information about
   * the directory server, including the capabilities that it provides and the
   * type of data that it is configured to handle.
   *
   * @return  The directory server root DSE, or {@code null} if it is not
   *          available.
   *
   * @throws  LDAPException  If a problem occurs while attempting to retrieve
   *                         the server root DSE.
   */
  public RootDSE getRootDSE()
         throws LDAPException
  {
    return RootDSE.getRootDSE(this);
  }



  /**
   * Retrieves the directory server schema definitions, using the subschema
   * subentry DN contained in the server's root DSE.  For directory servers
   * containing a single schema, this should be sufficient for all purposes.
   * For servers with multiple schemas, it may be necessary to specify the DN
   * of the target entry for which to obtain the associated schema.
   *
   * @return  The directory server schema definitions, or {@code null} if the
   *          schema information could not be retrieved (e.g, the client does
   *          not have permission to read the server schema).
   *
   * @throws  LDAPException  If a problem occurs while attempting to retrieve
   *                         the server schema.
   */
  public Schema getSchema()
         throws LDAPException
  {
    return Schema.getSchema(this, "");
  }



  /**
   * Retrieves the directory server schema definitions that govern the specified
   * entry.  The subschemaSubentry attribute will be retrieved from the target
   * entry, and then the appropriate schema definitions will be loaded from the
   * entry referenced by that attribute.  This may be necessary to ensure
   * correct behavior in servers that support multiple schemas.
   *
   * @param  entryDN  The DN of the entry for which to retrieve the associated
   *                  schema definitions.  It may be {@code null} or an empty
   *                  string if the subschemaSubentry attribute should be
   *                  retrieved from the server's root DSE.
   *
   * @return  The directory server schema definitions, or {@code null} if the
   *          schema information could not be retrieved (e.g, the client does
   *          not have permission to read the server schema).
   *
   * @throws  LDAPException  If a problem occurs while attempting to retrieve
   *                         the server schema.
   */
  public Schema getSchema(final String entryDN)
         throws LDAPException
  {
    return Schema.getSchema(this, entryDN);
  }



  /**
   * Retrieves the entry with the specified DN.  All user attributes will be
   * requested in the entry to return.
   *
   * @param  dn  The DN of the entry to retrieve.  It must not be {@code null}.
   *
   * @return  The requested entry, or {@code null} if the target entry does not
   *          exist or no entry was returned (e.g., if the authenticated user
   *          does not have permission to read the target entry).
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  public SearchResultEntry getEntry(final String dn)
         throws LDAPException
  {
    return getEntry(dn, (String[]) null);
  }



  /**
   * Retrieves the entry with the specified DN.
   *
   * @param  dn          The DN of the entry to retrieve.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to request for the target entry.
   *                     If it is {@code null}, then all user attributes will be
   *                     requested.
   *
   * @return  The requested entry, or {@code null} if the target entry does not
   *          exist or no entry was returned (e.g., if the authenticated user
   *          does not have permission to read the target entry).
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  public SearchResultEntry getEntry(final String dn, final String... attributes)
         throws LDAPException
  {
    final Filter filter = Filter.createPresenceFilter("objectClass");

    final SearchResult result;
    try
    {
      final SearchRequest searchRequest =
           new SearchRequest(dn, SearchScope.BASE, DereferencePolicy.NEVER, 1,
                             0, false, filter, attributes);
      result = search(searchRequest);
    }
    catch (LDAPException le)
    {
      if (le.getResultCode().equals(ResultCode.NO_SUCH_OBJECT))
      {
        return null;
      }
      else
      {
        throw le;
      }
    }

    if (! result.getResultCode().equals(ResultCode.SUCCESS))
    {
      throw new LDAPException(result);
    }

    final List<SearchResultEntry> entryList = result.getSearchEntries();
    if (entryList.isEmpty())
    {
      return null;
    }
    else
    {
      return entryList.get(0);
    }
  }



  /**
   * Processes an abandon request with the provided information.
   *
   * @param  requestID  The async request ID for the request to abandon.
   *
   * @throws  LDAPException  If a problem occurs while sending the request to
   *                         the server.
   */
  public void abandon(final AsyncRequestID requestID)
         throws LDAPException
  {
    abandon(requestID, null);
  }



  /**
   * Processes an abandon request with the provided information.
   *
   * @param  requestID  The async request ID for the request to abandon.
   * @param  controls   The set of controls to include in the abandon request.
   *                    It may be {@code null} or empty if there are no
   *                    controls.
   *
   * @throws  LDAPException  If a problem occurs while sending the request to
   *                         the server.
   */
  public void abandon(final AsyncRequestID requestID, final Control[] controls)
         throws LDAPException
  {
    if (debugEnabled(DebugType.LDAP))
    {
      debug(Level.INFO, DebugType.LDAP,
            "Sending LDAP abandon request for message ID " + requestID);
    }

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ABANDON_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    final int messageID = requestID.getMessageID();
    try
    {
      connectionInternals.getConnectionReader().deregisterResponseAcceptor(
           messageID);
    }
    catch (final Exception e)
    {
      debugException(e);
    }

    connectionStatistics.incrementNumAbandonRequests();
    sendMessage(new LDAPMessage(nextMessageID(),
         new AbandonRequestProtocolOp(messageID), controls));
  }



  /**
   * Sends an abandon request with the provided information.
   *
   * @param  messageID  The message ID for the request to abandon.
   * @param  controls   The set of controls to include in the abandon request.
   *                    It may be {@code null} or empty if there are no
   *                    controls.
   *
   * @throws  LDAPException  If a problem occurs while sending the request to
   *                         the server.
   */
  void abandon(final int messageID, final Control... controls)
       throws LDAPException
  {
    if (debugEnabled(DebugType.LDAP))
    {
      debug(Level.INFO, DebugType.LDAP,
            "Sending LDAP abandon request for message ID " + messageID);
    }

    try
    {
      connectionInternals.getConnectionReader().deregisterResponseAcceptor(
           messageID);
    }
    catch (final Exception e)
    {
      debugException(e);
    }

    connectionStatistics.incrementNumAbandonRequests();
    sendMessage(new LDAPMessage(nextMessageID(),
         new AbandonRequestProtocolOp(messageID), controls));
  }



  /**
   * Processes an add operation with the provided information.
   *
   * @param  dn          The DN of the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult add(final String dn, final Attribute... attributes)
         throws LDAPException
  {
    ensureNotNull(dn, attributes);

    return add(new AddRequest(dn, attributes));
  }



  /**
   * Processes an add operation with the provided information.
   *
   * @param  dn          The DN of the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult add(final String dn, final Collection<Attribute> attributes)
         throws LDAPException
  {
    ensureNotNull(dn, attributes);

    return add(new AddRequest(dn, attributes));
  }



  /**
   * Processes an add operation with the provided information.
   *
   * @param  entry  The entry to add.  It must not be {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult add(final Entry entry)
         throws LDAPException
  {
    ensureNotNull(entry);

    return add(new AddRequest(entry));
  }



  /**
   * Processes an add operation with the provided information.
   *
   * @param  ldifLines  The lines that comprise an LDIF representation of the
   *                    entry to add.  It must not be empty or {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDIFException  If the provided entry lines cannot be decoded as an
   *                         entry in LDIF form.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult add(final String... ldifLines)
         throws LDIFException, LDAPException
  {
    return add(new AddRequest(ldifLines));
  }



  /**
   * Processes the provided add request.
   *
   * @param  addRequest  The add request to be processed.  It must not be
   *                     {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult add(final AddRequest addRequest)
         throws LDAPException
  {
    ensureNotNull(addRequest);

    final LDAPResult ldapResult = addRequest.process(this, 1);

    switch (ldapResult.getResultCode().intValue())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;

      default:
        throw new LDAPException(ldapResult);
    }
  }



  /**
   * Processes the provided add request.
   *
   * @param  addRequest  The add request to be processed.  It must not be
   *                     {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult add(final ReadOnlyAddRequest addRequest)
         throws LDAPException
  {
    return add((AddRequest) addRequest);
  }



  /**
   * Processes the provided add request as an asynchronous operation.
   *
   * @param  addRequest      The add request to be processed.  It must not be
   *                         {@code null}.
   * @param  resultListener  The async result listener to use to handle the
   *                         response for the add operation.  It may be
   *                         {@code null} if the result is going to be obtained
   *                         from the returned {@code AsyncRequestID} object via
   *                         the {@code Future} API.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public AsyncRequestID asyncAdd(final AddRequest addRequest,
                                 final AsyncResultListener resultListener)
         throws LDAPException
  {
    ensureNotNull(addRequest);

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    final AsyncResultListener listener;
    if (resultListener == null)
    {
      listener = DiscardAsyncListener.getInstance();
    }
    else
    {
      listener = resultListener;
    }

    return addRequest.processAsync(this, listener);
  }



  /**
   * Processes the provided add request as an asynchronous operation.
   *
   * @param  addRequest      The add request to be processed.  It must not be
   *                         {@code null}.
   * @param  resultListener  The async result listener to use to handle the
   *                         response for the add operation.  It may be
   *                         {@code null} if the result is going to be obtained
   *                         from the returned {@code AsyncRequestID} object via
   *                         the {@code Future} API.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public AsyncRequestID asyncAdd(final ReadOnlyAddRequest addRequest,
                                 final AsyncResultListener resultListener)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncAdd((AddRequest) addRequest, resultListener);
  }



  /**
   * Processes a simple bind request with the provided DN and password.
   * <BR><BR>
   * The LDAP protocol specification forbids clients from attempting to perform
   * a bind on a connection in which one or more other operations are already in
   * progress.  If a bind is attempted while any operations are in progress,
   * then the directory server may or may not abort processing for those
   * operations, depending on the type of operation and how far along the
   * server has already gotten while processing that operation (unless the bind
   * request is one that will not cause the server to attempt to change the
   * identity of this connection, for example by including the retain identity
   * request control in the bind request if using the Commercial Edition of the
   * LDAP SDK in conjunction with an UnboundID Directory Server).  It is
   * recommended that all active operations be abandoned, canceled, or allowed
   * to complete before attempting to perform a bind on an active connection.
   *
   * @param  bindDN    The bind DN for the bind operation.
   * @param  password  The password for the simple bind operation.
   *
   * @return  The result of processing the bind operation.
   *
   * @throws  LDAPException  If the server rejects the bind request, or if a
   *                         problem occurs while sending the request or reading
   *                         the response.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public BindResult bind(final String bindDN, final String password)
         throws LDAPException
  {
    return bind(new SimpleBindRequest(bindDN, password));
  }



  /**
   * Processes the provided bind request.
   * <BR><BR>
   * The LDAP protocol specification forbids clients from attempting to perform
   * a bind on a connection in which one or more other operations are already in
   * progress.  If a bind is attempted while any operations are in progress,
   * then the directory server may or may not abort processing for those
   * operations, depending on the type of operation and how far along the
   * server has already gotten while processing that operation (unless the bind
   * request is one that will not cause the server to attempt to change the
   * identity of this connection, for example by including the retain identity
   * request control in the bind request if using the Commercial Edition of the
   * LDAP SDK in conjunction with an UnboundID Directory Server).  It is
   * recommended that all active operations be abandoned, canceled, or allowed
   * to complete before attempting to perform a bind on an active connection.
   *
   * @param  bindRequest  The bind request to be processed.  It must not be
   *                      {@code null}.
   *
   * @return  The result of processing the bind operation.
   *
   * @throws  LDAPException  If the server rejects the bind request, or if a
   *                         problem occurs while sending the request or reading
   *                         the response.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public BindResult bind(final BindRequest bindRequest)
         throws LDAPException
  {
    ensureNotNull(bindRequest);

    // We don't want to update the last bind request or update the cached
    // schema for this connection if it included the retain identity control.
    // However, that's only available in the Commercial Edition, so just
    // reference it by OID here.
    boolean hasRetainIdentityControl = false;
    for (final Control c : bindRequest.getControls())
    {
      if (c.getOID().equals("1.3.6.1.4.1.30221.2.5.3"))
      {
        hasRetainIdentityControl = true;
        break;
      }
    }

    if (! hasRetainIdentityControl)
    {
      lastBindRequest = null;
    }

    final BindResult bindResult = bindRequest.process(this, 1);
    if (bindResult.getResultCode().equals(ResultCode.SUCCESS))
    {
      if (! hasRetainIdentityControl)
      {
        lastBindRequest = bindRequest;
        if (connectionOptions.useSchema())
        {
          try
          {
            cachedSchema = getCachedSchema(this);
          }
          catch (Exception e)
          {
            debugException(e);
          }
        }
      }

      return bindResult;
    }

    if (bindResult.getResultCode().equals(ResultCode.SASL_BIND_IN_PROGRESS))
    {
      throw new SASLBindInProgressException(bindResult);
    }
    else
    {
      throw new LDAPException(bindResult);
    }
  }



  /**
   * Processes a compare operation with the provided information.
   *
   * @param  dn              The DN of the entry in which to make the
   *                         comparison.  It must not be {@code null}.
   * @param  attributeName   The attribute name for which to make the
   *                         comparison.  It must not be {@code null}.
   * @param  assertionValue  The assertion value to verify in the target entry.
   *                         It must not be {@code null}.
   *
   * @return  The result of processing the compare operation.
   *
   * @throws  LDAPException  If the server rejects the compare request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public CompareResult compare(final String dn, final String attributeName,
                               final String assertionValue)
         throws LDAPException
  {
    ensureNotNull(dn, attributeName, assertionValue);

    return compare(new CompareRequest(dn, attributeName, assertionValue));
  }



  /**
   * Processes the provided compare request.
   *
   * @param  compareRequest  The compare request to be processed.  It must not
   *                         be {@code null}.
   *
   * @return  The result of processing the compare operation.
   *
   * @throws  LDAPException  If the server rejects the compare request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public CompareResult compare(final CompareRequest compareRequest)
         throws LDAPException
  {
    ensureNotNull(compareRequest);

    final LDAPResult result = compareRequest.process(this, 1);
    switch (result.getResultCode().intValue())
    {
      case ResultCode.COMPARE_FALSE_INT_VALUE:
      case ResultCode.COMPARE_TRUE_INT_VALUE:
        return new CompareResult(result);

      default:
        throw new LDAPException(result);
    }
  }



  /**
   * Processes the provided compare request.
   *
   * @param  compareRequest  The compare request to be processed.  It must not
   *                         be {@code null}.
   *
   * @return  The result of processing the compare operation.
   *
   * @throws  LDAPException  If the server rejects the compare request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public CompareResult compare(final ReadOnlyCompareRequest compareRequest)
         throws LDAPException
  {
    return compare((CompareRequest) compareRequest);
  }



  /**
   * Processes the provided compare request as an asynchronous operation.
   *
   * @param  compareRequest  The compare request to be processed.  It must not
   *                         be {@code null}.
   * @param  resultListener  The async result listener to use to handle the
   *                         response for the compare operation.  It may be
   *                         {@code null} if the result is going to be obtained
   *                         from the returned {@code AsyncRequestID} object via
   *                         the {@code Future} API.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public AsyncRequestID asyncCompare(final CompareRequest compareRequest,
                             final AsyncCompareResultListener resultListener)
         throws LDAPException
  {
    ensureNotNull(compareRequest);

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    final AsyncCompareResultListener listener;
    if (resultListener == null)
    {
      listener = DiscardAsyncListener.getInstance();
    }
    else
    {
      listener = resultListener;
    }

    return compareRequest.processAsync(this, listener);
  }



  /**
   * Processes the provided compare request as an asynchronous operation.
   *
   * @param  compareRequest  The compare request to be processed.  It must not
   *                         be {@code null}.
   * @param  resultListener  The async result listener to use to handle the
   *                         response for the compare operation.  It may be
   *                         {@code null} if the result is going to be obtained
   *                         from the returned {@code AsyncRequestID} object via
   *                         the {@code Future} API.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public AsyncRequestID asyncCompare(
                             final ReadOnlyCompareRequest compareRequest,
                             final AsyncCompareResultListener resultListener)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncCompare((CompareRequest) compareRequest, resultListener);
  }



  /**
   * Deletes the entry with the specified DN.
   *
   * @param  dn  The DN of the entry to delete.  It must not be {@code null}.
   *
   * @return  The result of processing the delete operation.
   *
   * @throws  LDAPException  If the server rejects the delete request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult delete(final String dn)
         throws LDAPException
  {
    return delete(new DeleteRequest(dn));
  }



  /**
   * Processes the provided delete request.
   *
   * @param  deleteRequest  The delete request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  The result of processing the delete operation.
   *
   * @throws  LDAPException  If the server rejects the delete request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult delete(final DeleteRequest deleteRequest)
         throws LDAPException
  {
    ensureNotNull(deleteRequest);

    final LDAPResult ldapResult = deleteRequest.process(this, 1);

    switch (ldapResult.getResultCode().intValue())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;

      default:
        throw new LDAPException(ldapResult);
    }
  }



  /**
   * Processes the provided delete request.
   *
   * @param  deleteRequest  The delete request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  The result of processing the delete operation.
   *
   * @throws  LDAPException  If the server rejects the delete request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult delete(final ReadOnlyDeleteRequest deleteRequest)
         throws LDAPException
  {
    return delete((DeleteRequest) deleteRequest);
  }



  /**
   * Processes the provided delete request as an asynchronous operation.
   *
   * @param  deleteRequest   The delete request to be processed.  It must not be
   *                         {@code null}.
   * @param  resultListener  The async result listener to use to handle the
   *                         response for the delete operation.  It may be
   *                         {@code null} if the result is going to be obtained
   *                         from the returned {@code AsyncRequestID} object via
   *                         the {@code Future} API.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public AsyncRequestID asyncDelete(final DeleteRequest deleteRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    ensureNotNull(deleteRequest);

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    final AsyncResultListener listener;
    if (resultListener == null)
    {
      listener = DiscardAsyncListener.getInstance();
    }
    else
    {
      listener = resultListener;
    }

    return deleteRequest.processAsync(this, listener);
  }



  /**
   * Processes the provided delete request as an asynchronous operation.
   *
   * @param  deleteRequest   The delete request to be processed.  It must not be
   *                         {@code null}.
   * @param  resultListener  The async result listener to use to handle the
   *                         response for the delete operation.  It may be
   *                         {@code null} if the result is going to be obtained
   *                         from the returned {@code AsyncRequestID} object via
   *                         the {@code Future} API.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public AsyncRequestID asyncDelete(final ReadOnlyDeleteRequest deleteRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncDelete((DeleteRequest) deleteRequest, resultListener);
  }



  /**
   * Processes an extended request with the provided request OID.  Note that
   * because some types of extended operations return unusual result codes under
   * "normal" conditions, the server may not always throw an exception for a
   * failed extended operation like it does for other types of operations.  It
   * will throw an exception under conditions where there appears to be a
   * problem with the connection or the server to which the connection is
   * established, but there may be many circumstances in which an extended
   * operation is not processed correctly but this method does not throw an
   * exception.  In the event that no exception is thrown, it is the
   * responsibility of the caller to interpret the result to determine whether
   * the operation was processed as expected.
   * <BR><BR>
   * Note that extended operations which may change the state of this connection
   * (e.g., the StartTLS extended operation, which will add encryption to a
   * previously-unencrypted connection) should not be invoked while any other
   * operations are active on the connection.  It is recommended that all active
   * operations be abandoned, canceled, or allowed to complete before attempting
   * to process an extended operation that may change the state of this
   * connection.
   *
   * @param  requestOID  The OID for the extended request to process.  It must
   *                     not be {@code null}.
   *
   * @return  The extended result object that provides information about the
   *          result of the request processing.  It may or may not indicate that
   *          the operation was successful.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public ExtendedResult processExtendedOperation(final String requestOID)
         throws LDAPException
  {
    ensureNotNull(requestOID);

    return processExtendedOperation(new ExtendedRequest(requestOID));
  }



  /**
   * Processes an extended request with the provided request OID and value.
   * Note that because some types of extended operations return unusual result
   * codes under "normal" conditions, the server may not always throw an
   * exception for a failed extended operation like it does for other types of
   * operations.  It will throw an exception under conditions where there
   * appears to be a problem with the connection or the server to which the
   * connection is established, but there may be many circumstances in which an
   * extended operation is not processed correctly but this method does not
   * throw an exception.  In the event that no exception is thrown, it is the
   * responsibility of the caller to interpret the result to determine whether
   * the operation was processed as expected.
   * <BR><BR>
   * Note that extended operations which may change the state of this connection
   * (e.g., the StartTLS extended operation, which will add encryption to a
   * previously-unencrypted connection) should not be invoked while any other
   * operations are active on the connection.  It is recommended that all active
   * operations be abandoned, canceled, or allowed to complete before attempting
   * to process an extended operation that may change the state of this
   * connection.
   *
   * @param  requestOID    The OID for the extended request to process.  It must
   *                       not be {@code null}.
   * @param  requestValue  The encoded value for the extended request to
   *                       process.  It may be {@code null} if there does not
   *                       need to be a value for the requested operation.
   *
   * @return  The extended result object that provides information about the
   *          result of the request processing.  It may or may not indicate that
   *          the operation was successful.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public ExtendedResult processExtendedOperation(final String requestOID,
                             final ASN1OctetString requestValue)
         throws LDAPException
  {
    ensureNotNull(requestOID);

    return processExtendedOperation(new ExtendedRequest(requestOID,
                                                        requestValue));
  }



  /**
   * Processes the provided extended request.  Note that because some types of
   * extended operations return unusual result codes under "normal" conditions,
   * the server may not always throw an exception for a failed extended
   * operation like it does for other types of operations.  It will throw an
   * exception under conditions where there appears to be a problem with the
   * connection or the server to which the connection is established, but there
   * may be many circumstances in which an extended operation is not processed
   * correctly but this method does not throw an exception.  In the event that
   * no exception is thrown, it is the responsibility of the caller to interpret
   * the result to determine whether the operation was processed as expected.
   * <BR><BR>
   * Note that extended operations which may change the state of this connection
   * (e.g., the StartTLS extended operation, which will add encryption to a
   * previously-unencrypted connection) should not be invoked while any other
   * operations are active on the connection.  It is recommended that all active
   * operations be abandoned, canceled, or allowed to complete before attempting
   * to process an extended operation that may change the state of this
   * connection.
   *
   * @param  extendedRequest  The extended request to be processed.  It must not
   *                          be {@code null}.
   *
   * @return  The extended result object that provides information about the
   *          result of the request processing.  It may or may not indicate that
   *          the operation was successful.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public ExtendedResult processExtendedOperation(
                               final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    ensureNotNull(extendedRequest);

    final ExtendedResult extendedResult = extendedRequest.process(this, 1);

    if ((extendedResult.getOID() == null) &&
        (extendedResult.getValue() == null))
    {
      switch (extendedResult.getResultCode().intValue())
      {
        case ResultCode.OPERATIONS_ERROR_INT_VALUE:
        case ResultCode.PROTOCOL_ERROR_INT_VALUE:
        case ResultCode.BUSY_INT_VALUE:
        case ResultCode.UNAVAILABLE_INT_VALUE:
        case ResultCode.OTHER_INT_VALUE:
        case ResultCode.SERVER_DOWN_INT_VALUE:
        case ResultCode.LOCAL_ERROR_INT_VALUE:
        case ResultCode.ENCODING_ERROR_INT_VALUE:
        case ResultCode.DECODING_ERROR_INT_VALUE:
        case ResultCode.TIMEOUT_INT_VALUE:
        case ResultCode.NO_MEMORY_INT_VALUE:
        case ResultCode.CONNECT_ERROR_INT_VALUE:
          throw new LDAPException(extendedResult);
      }
    }

    if ((extendedResult.getResultCode() == ResultCode.SUCCESS) &&
         extendedRequest.getOID().equals(
              StartTLSExtendedRequest.STARTTLS_REQUEST_OID))
    {
      startTLSRequest = extendedRequest.duplicate();
    }

    return extendedResult;
  }



  /**
   * Applies the provided modification to the specified entry.
   *
   * @param  dn   The DN of the entry to modify.  It must not be {@code null}.
   * @param  mod  The modification to apply to the target entry.  It must not
   *              be {@code null}.
   *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult modify(final String dn, final Modification mod)
         throws LDAPException
  {
    ensureNotNull(dn, mod);

    return modify(new ModifyRequest(dn, mod));
  }



  /**
   * Applies the provided set of modifications to the specified entry.
   *
   * @param  dn    The DN of the entry to modify.  It must not be {@code null}.
   * @param  mods  The set of modifications to apply to the target entry.  It
   *               must not be {@code null} or empty.  *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult modify(final String dn, final Modification... mods)
         throws LDAPException
  {
    ensureNotNull(dn, mods);

    return modify(new ModifyRequest(dn, mods));
  }



  /**
   * Applies the provided set of modifications to the specified entry.
   *
   * @param  dn    The DN of the entry to modify.  It must not be {@code null}.
   * @param  mods  The set of modifications to apply to the target entry.  It
   *               must not be {@code null} or empty.
   *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult modify(final String dn, final List<Modification> mods)
         throws LDAPException
  {
    ensureNotNull(dn, mods);

    return modify(new ModifyRequest(dn, mods));
  }



  /**
   * Processes a modify request from the provided LDIF representation of the
   * changes.
   *
   * @param  ldifModificationLines  The lines that comprise an LDIF
   *                                representation of a modify change record.
   *                                It must not be {@code null} or empty.
   *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDIFException  If the provided set of lines cannot be parsed as an
   *                         LDIF modify change record.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   *
   */
  public LDAPResult modify(final String... ldifModificationLines)
         throws LDIFException, LDAPException
  {
    ensureNotNull(ldifModificationLines);

    return modify(new ModifyRequest(ldifModificationLines));
  }



  /**
   * Processes the provided modify request.
   *
   * @param  modifyRequest  The modify request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult modify(final ModifyRequest modifyRequest)
         throws LDAPException
  {
    ensureNotNull(modifyRequest);

    final LDAPResult ldapResult = modifyRequest.process(this, 1);

    switch (ldapResult.getResultCode().intValue())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;

      default:
        throw new LDAPException(ldapResult);
    }
  }



  /**
   * Processes the provided modify request.
   *
   * @param  modifyRequest  The modify request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  The result of processing the modify operation.
   *
   * @throws  LDAPException  If the server rejects the modify request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  public LDAPResult modify(final ReadOnlyModifyRequest modifyRequest)
         throws LDAPException
  {
    return modify((ModifyRequest) modifyRequest);
  }



  /**
   * Processes the provided modify request as an asynchronous operation.
   *
   * @param  modifyRequest   The modify request to be processed.  It must not be
   *                         {@code null}.
   * @param  resultListener  The async result listener to use to handle the
   *                         response for the modify operation.  It may be
   *                         {@code null} if the result is going to be obtained
   *                         from the returned {@code AsyncRequestID} object via
   *                         the {@code Future} API.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public AsyncRequestID asyncModify(final ModifyRequest modifyRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    ensureNotNull(modifyRequest);

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    final AsyncResultListener listener;
    if (resultListener == null)
    {
      listener = DiscardAsyncListener.getInstance();
    }
    else
    {
      listener = resultListener;
    }

    return modifyRequest.processAsync(this, listener);
  }



  /**
   * Processes the provided modify request as an asynchronous operation.
   *
   * @param  modifyRequest   The modify request to be processed.  It must not be
   *                         {@code null}.
   * @param  resultListener  The async result listener to use to handle the
   *                         response for the modify operation.  It may be
   *                         {@code null} if the result is going to be obtained
   *                         from the returned {@code AsyncRequestID} object via
   *                         the {@code Future} API.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public AsyncRequestID asyncModify(final ReadOnlyModifyRequest modifyRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncModify((ModifyRequest) modifyRequest, resultListener);
  }



  /**
   * Performs a modify DN operation with the provided information.
   *
   * @param  dn            The current DN for the entry to rename.  It must not
   *                       be {@code null}.
   * @param  newRDN        The new RDN to use for the entry.  It must not be
   *                       {@code null}.
   * @param  deleteOldRDN  Indicates whether to delete the current RDN value
   *                       from the entry.
   *
   * @return  The result of processing the modify DN operation.
   *
   * @throws  LDAPException  If the server rejects the modify DN request, or if
   *                         a problem is encountered while sending the request
   *                         or reading the response.
   */
  public LDAPResult modifyDN(final String dn, final String newRDN,
                             final boolean deleteOldRDN)
         throws LDAPException
  {
    ensureNotNull(dn, newRDN);

    return modifyDN(new ModifyDNRequest(dn, newRDN, deleteOldRDN));
  }



  /**
   * Performs a modify DN operation with the provided information.
   *
   * @param  dn             The current DN for the entry to rename.  It must not
   *                        be {@code null}.
   * @param  newRDN         The new RDN to use for the entry.  It must not be
   *                        {@code null}.
   * @param  deleteOldRDN   Indicates whether to delete the current RDN value
   *                        from the entry.
   * @param  newSuperiorDN  The new superior DN for the entry.  It may be
   *                        {@code null} if the entry is not to be moved below a
   *                        new parent.
   *
   * @return  The result of processing the modify DN operation.
   *
   * @throws  LDAPException  If the server rejects the modify DN request, or if
   *                         a problem is encountered while sending the request
   *                         or reading the response.
   */
  public LDAPResult modifyDN(final String dn, final String newRDN,
                             final boolean deleteOldRDN,
                             final String newSuperiorDN)
         throws LDAPException
  {
    ensureNotNull(dn, newRDN);

    return modifyDN(new ModifyDNRequest(dn, newRDN, deleteOldRDN,
                                        newSuperiorDN));
  }



  /**
   * Processes the provided modify DN request.
   *
   * @param  modifyDNRequest  The modify DN request to be processed.  It must
   *                          not be {@code null}.
   *
   * @return  The result of processing the modify DN operation.
   *
   * @throws  LDAPException  If the server rejects the modify DN request, or if
   *                         a problem is encountered while sending the request
   *                         or reading the response.
   */
  public LDAPResult modifyDN(final ModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    ensureNotNull(modifyDNRequest);

    final LDAPResult ldapResult = modifyDNRequest.process(this, 1);

    switch (ldapResult.getResultCode().intValue())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;

      default:
        throw new LDAPException(ldapResult);
    }
  }



  /**
   * Processes the provided modify DN request.
   *
   * @param  modifyDNRequest  The modify DN request to be processed.  It must
   *                          not be {@code null}.
   *
   * @return  The result of processing the modify DN operation.
   *
   * @throws  LDAPException  If the server rejects the modify DN request, or if
   *                         a problem is encountered while sending the request
   *                         or reading the response.
   */
  public LDAPResult modifyDN(final ReadOnlyModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return modifyDN((ModifyDNRequest) modifyDNRequest);
  }



  /**
   * Processes the provided modify DN request as an asynchronous operation.
   *
   * @param  modifyDNRequest  The modify DN request to be processed.  It must
   *                          not be {@code null}.
   * @param  resultListener  The async result listener to use to handle the
   *                         response for the modify DN operation.  It may be
   *                         {@code null} if the result is going to be obtained
   *                         from the returned {@code AsyncRequestID} object via
   *                         the {@code Future} API.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public AsyncRequestID asyncModifyDN(final ModifyDNRequest modifyDNRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    ensureNotNull(modifyDNRequest);

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    final AsyncResultListener listener;
    if (resultListener == null)
    {
      listener = DiscardAsyncListener.getInstance();
    }
    else
    {
      listener = resultListener;
    }

    return modifyDNRequest.processAsync(this, listener);
  }



  /**
   * Processes the provided modify DN request as an asynchronous operation.
   *
   * @param  modifyDNRequest  The modify DN request to be processed.  It must
   *                          not be {@code null}.
   * @param  resultListener  The async result listener to use to handle the
   *                         response for the modify DN operation.  It may be
   *                         {@code null} if the result is going to be obtained
   *                         from the returned {@code AsyncRequestID} object via
   *                         the {@code Future} API.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  public AsyncRequestID asyncModifyDN(
                             final ReadOnlyModifyDNRequest modifyDNRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncModifyDN((ModifyDNRequest) modifyDNRequest, resultListener);
  }



  /**
   * Processes a search operation with the provided information.  The search
   * result entries and references will be collected internally and included in
   * the {@code SearchResult} object that is returned.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN      The base DN for the search request.  It must not be
   *                     {@code null}.
   * @param  scope       The scope that specifies the range of entries that
   *                     should be examined for the search.
   * @param  filter      The string representation of the filter to use to
   *                     identify matching entries.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes that should be returned in
   *                     matching entries.  It may be {@code null} or empty if
   *                     the default attribute set (all user attributes) is to
   *                     be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, including the set of matching entries
   *          and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while parsing
   *                               the provided filter string, sending the
   *                               request, or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final String filter, final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    try
    {
      return search(new SearchRequest(baseDN, scope, filter, attributes));
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }
  }



  /**
   * Processes a search operation with the provided information.  The search
   * result entries and references will be collected internally and included in
   * the {@code SearchResult} object that is returned.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN      The base DN for the search request.  It must not be
   *                     {@code null}.
   * @param  scope       The scope that specifies the range of entries that
   *                     should be examined for the search.
   * @param  filter      The filter to use to identify matching entries.  It
   *                     must not be {@code null}.
   * @param  attributes  The set of attributes that should be returned in
   *                     matching entries.  It may be {@code null} or empty if
   *                     the default attribute set (all user attributes) is to
   *                     be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, including the set of matching entries
   *          and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final Filter filter, final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    return search(new SearchRequest(baseDN, scope, filter, attributes));
  }



  /**
   * Processes a search operation with the provided information.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchResultListener  The search result listener that should be
   *                               used to return results to the client.  It may
   *                               be {@code null} if the search results should
   *                               be collected internally and returned in the
   *                               {@code SearchResult} object.
   * @param  baseDN                The base DN for the search request.  It must
   *                               not be {@code null}.
   * @param  scope                 The scope that specifies the range of entries
   *                               that should be examined for the search.
   * @param  filter                The string representation of the filter to
   *                               use to identify matching entries.  It must
   *                               not be {@code null}.
   * @param  attributes            The set of attributes that should be returned
   *                               in matching entries.  It may be {@code null}
   *                               or empty if the default attribute set (all
   *                               user attributes) is to be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while parsing
   *                               the provided filter string, sending the
   *                               request, or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final String filter, final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    try
    {
      return search(new SearchRequest(searchResultListener, baseDN, scope,
                                      filter, attributes));
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }
  }



  /**
   * Processes a search operation with the provided information.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchResultListener  The search result listener that should be
   *                               used to return results to the client.  It may
   *                               be {@code null} if the search results should
   *                               be collected internally and returned in the
   *                               {@code SearchResult} object.
   * @param  baseDN                The base DN for the search request.  It must
   *                               not be {@code null}.
   * @param  scope                 The scope that specifies the range of entries
   *                               that should be examined for the search.
   * @param  filter                The filter to use to identify matching
   *                               entries.  It must not be {@code null}.
   * @param  attributes            The set of attributes that should be returned
   *                               in matching entries.  It may be {@code null}
   *                               or empty if the default attribute set (all
   *                               user attributes) is to be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final Filter filter, final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    try
    {
      return search(new SearchRequest(searchResultListener, baseDN, scope,
                                      filter, attributes));
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }
  }



  /**
   * Processes a search operation with the provided information.  The search
   * result entries and references will be collected internally and included in
   * the {@code SearchResult} object that is returned.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN       The base DN for the search request.  It must not be
   *                      {@code null}.
   * @param  scope        The scope that specifies the range of entries that
   *                      should be examined for the search.
   * @param  derefPolicy  The dereference policy the server should use for any
   *                      aliases encountered while processing the search.
   * @param  sizeLimit    The maximum number of entries that the server should
   *                      return for the search.  A value of zero indicates that
   *                      there should be no limit.
   * @param  timeLimit    The maximum length of time in seconds that the server
   *                      should spend processing this search request.  A value
   *                      of zero indicates that there should be no limit.
   * @param  typesOnly    Indicates whether to return only attribute names in
   *                      matching entries, or both attribute names and values.
   * @param  filter       The string representation of the filter to use to
   *                      identify matching entries.  It must not be
   *                      {@code null}.
   * @param  attributes   The set of attributes that should be returned in
   *                      matching entries.  It may be {@code null} or empty if
   *                      the default attribute set (all user attributes) is to
   *                      be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, including the set of matching entries
   *          and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while parsing
   *                               the provided filter string, sending the
   *                               request, or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final String filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    try
    {
      return search(new SearchRequest(baseDN, scope, derefPolicy, sizeLimit,
                                      timeLimit, typesOnly, filter,
                                      attributes));
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }
  }



  /**
   * Processes a search operation with the provided information.  The search
   * result entries and references will be collected internally and included in
   * the {@code SearchResult} object that is returned.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN       The base DN for the search request.  It must not be
   *                      {@code null}.
   * @param  scope        The scope that specifies the range of entries that
   *                      should be examined for the search.
   * @param  derefPolicy  The dereference policy the server should use for any
   *                      aliases encountered while processing the search.
   * @param  sizeLimit    The maximum number of entries that the server should
   *                      return for the search.  A value of zero indicates that
   *                      there should be no limit.
   * @param  timeLimit    The maximum length of time in seconds that the server
   *                      should spend processing this search request.  A value
   *                      of zero indicates that there should be no limit.
   * @param  typesOnly    Indicates whether to return only attribute names in
   *                      matching entries, or both attribute names and values.
   * @param  filter       The filter to use to identify matching entries.  It
   *                      must not be {@code null}.
   * @param  attributes   The set of attributes that should be returned in
   *                      matching entries.  It may be {@code null} or empty if
   *                      the default attribute set (all user attributes) is to
   *                      be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, including the set of matching entries
   *          and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final Filter filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    return search(new SearchRequest(baseDN, scope, derefPolicy, sizeLimit,
                                    timeLimit, typesOnly, filter, attributes));
  }



  /**
   * Processes a search operation with the provided information.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchResultListener  The search result listener that should be
   *                               used to return results to the client.  It may
   *                               be {@code null} if the search results should
   *                               be collected internally and returned in the
   *                               {@code SearchResult} object.
   * @param  baseDN                The base DN for the search request.  It must
   *                               not be {@code null}.
   * @param  scope                 The scope that specifies the range of entries
   *                               that should be examined for the search.
   * @param  derefPolicy           The dereference policy the server should use
   *                               for any aliases encountered while processing
   *                               the search.
   * @param  sizeLimit             The maximum number of entries that the server
   *                               should return for the search.  A value of
   *                               zero indicates that there should be no limit.
   * @param  timeLimit             The maximum length of time in seconds that
   *                               the server should spend processing this
   *                               search request.  A value of zero indicates
   *                               that there should be no limit.
   * @param  typesOnly             Indicates whether to return only attribute
   *                               names in matching entries, or both attribute
   *                               names and values.
   * @param  filter                The string representation of the filter to
   *                               use to identify matching entries.  It must
   *                               not be {@code null}.
   * @param  attributes            The set of attributes that should be returned
   *                               in matching entries.  It may be {@code null}
   *                               or empty if the default attribute set (all
   *                               user attributes) is to be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while parsing
   *                               the provided filter string, sending the
   *                               request, or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final String filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    try
    {
      return search(new SearchRequest(searchResultListener, baseDN, scope,
                                      derefPolicy, sizeLimit, timeLimit,
                                      typesOnly, filter, attributes));
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }
  }



  /**
   * Processes a search operation with the provided information.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchResultListener  The search result listener that should be
   *                               used to return results to the client.  It may
   *                               be {@code null} if the search results should
   *                               be collected internally and returned in the
   *                               {@code SearchResult} object.
   * @param  baseDN                The base DN for the search request.  It must
   *                               not be {@code null}.
   * @param  scope                 The scope that specifies the range of entries
   *                               that should be examined for the search.
   * @param  derefPolicy           The dereference policy the server should use
   *                               for any aliases encountered while processing
   *                               the search.
   * @param  sizeLimit             The maximum number of entries that the server
   *                               should return for the search.  A value of
   *                               zero indicates that there should be no limit.
   * @param  timeLimit             The maximum length of time in seconds that
   *                               the server should spend processing this
   *                               search request.  A value of zero indicates
   *                               that there should be no limit.
   * @param  typesOnly             Indicates whether to return only attribute
   *                               names in matching entries, or both attribute
   *                               names and values.
   * @param  filter                The filter to use to identify matching
   *                               entries.  It must not be {@code null}.
   * @param  attributes            The set of attributes that should be returned
   *                               in matching entries.  It may be {@code null}
   *                               or empty if the default attribute set (all
   *                               user attributes) is to be requested.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final Filter filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    return search(new SearchRequest(searchResultListener, baseDN, scope,
                                    derefPolicy, sizeLimit, timeLimit,
                                    typesOnly, filter, attributes));
  }



  /**
   * Processes the provided search request.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchRequest  The search request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResult search(final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    ensureNotNull(searchRequest);

    final SearchResult searchResult;
    try
    {
      searchResult = searchRequest.process(this, 1);
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    if (! searchResult.getResultCode().equals(ResultCode.SUCCESS))
    {
      throw new LDAPSearchException(searchResult);
    }

    return searchResult;
  }



  /**
   * Processes the provided search request.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references (although if a search result listener was provided,
   * then it will have been used to make any entries and references available,
   * and they will not be available through the {@code getSearchEntries} and
   * {@code getSearchReferences} methods).
   *
   * @param  searchRequest  The search request to be processed.  It must not be
   *                        {@code null}.
   *
   * @return  A search result object that provides information about the
   *          processing of the search, potentially including the set of
   *          matching entries and search references returned by the server.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               or if a problem is encountered while sending
   *                               the request or reading the response.  If one
   *                               or more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResult search(final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return search((SearchRequest) searchRequest);
  }



  /**
   * Processes a search operation with the provided information.  It is expected
   * that at most one entry will be returned from the search, and that no
   * additional content from the successful search result (e.g., diagnostic
   * message or response controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN      The base DN for the search request.  It must not be
   *                     {@code null}.
   * @param  scope       The scope that specifies the range of entries that
   *                     should be examined for the search.
   * @param  filter      The string representation of the filter to use to
   *                     identify matching entries.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes that should be returned in
   *                     matching entries.  It may be {@code null} or empty if
   *                     the default attribute set (all user attributes) is to
   *                     be requested.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final String filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    final SearchRequest r;
    try
    {
      r = new SearchRequest(baseDN, scope, DereferencePolicy.NEVER, 1, 0, false,
           filter, attributes);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    return searchForEntry(r);
  }



  /**
   * Processes a search operation with the provided information.  It is expected
   * that at most one entry will be returned from the search, and that no
   * additional content from the successful search result (e.g., diagnostic
   * message or response controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN      The base DN for the search request.  It must not be
   *                     {@code null}.
   * @param  scope       The scope that specifies the range of entries that
   *                     should be examined for the search.
   * @param  filter      The string representation of the filter to use to
   *                     identify matching entries.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes that should be returned in
   *                     matching entries.  It may be {@code null} or empty if
   *                     the default attribute set (all user attributes) is to
   *                     be requested.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final Filter filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope,
         DereferencePolicy.NEVER, 1, 0, false, filter, attributes));
  }



  /**
   * Processes a search operation with the provided information.  It is expected
   * that at most one entry will be returned from the search, and that no
   * additional content from the successful search result (e.g., diagnostic
   * message or response controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN       The base DN for the search request.  It must not be
   *                      {@code null}.
   * @param  scope        The scope that specifies the range of entries that
   *                      should be examined for the search.
   * @param  derefPolicy  The dereference policy the server should use for any
   *                      aliases encountered while processing the search.
   * @param  timeLimit    The maximum length of time in seconds that the server
   *                      should spend processing this search request.  A value
   *                      of zero indicates that there should be no limit.
   * @param  typesOnly    Indicates whether to return only attribute names in
   *                      matching entries, or both attribute names and values.
   * @param  filter       The string representation of the filter to use to
   *                      identify matching entries.  It must not be
   *                      {@code null}.
   * @param  attributes   The set of attributes that should be returned in
   *                      matching entries.  It may be {@code null} or empty if
   *                      the default attribute set (all user attributes) is to
   *                      be requested.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final DereferencePolicy derefPolicy,
                                          final int timeLimit,
                                          final boolean typesOnly,
                                          final String filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    final SearchRequest r;
    try
    {
      r = new SearchRequest(baseDN, scope, derefPolicy, 1, timeLimit, typesOnly,
           filter, attributes);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    return searchForEntry(r);
  }



  /**
   * Processes a search operation with the provided information.  It is expected
   * that at most one entry will be returned from the search, and that no
   * additional content from the successful search result (e.g., diagnostic
   * message or response controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  baseDN       The base DN for the search request.  It must not be
   *                      {@code null}.
   * @param  scope        The scope that specifies the range of entries that
   *                      should be examined for the search.
   * @param  derefPolicy  The dereference policy the server should use for any
   *                      aliases encountered while processing the search.
   * @param  timeLimit    The maximum length of time in seconds that the server
   *                      should spend processing this search request.  A value
   *                      of zero indicates that there should be no limit.
   * @param  typesOnly    Indicates whether to return only attribute names in
   *                      matching entries, or both attribute names and values.
   * @param  filter       The filter to use to identify matching entries.  It
   *                      must not be {@code null}.
   * @param  attributes   The set of attributes that should be returned in
   *                      matching entries.  It may be {@code null} or empty if
   *                      the default attribute set (all user attributes) is to
   *                      be requested.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final DereferencePolicy derefPolicy,
                                          final int timeLimit,
                                          final boolean typesOnly,
                                          final Filter filter,
                                          final String... attributes)
       throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope, derefPolicy, 1,
         timeLimit, typesOnly, filter, attributes));
  }



  /**
   * Processes the provided search request.  It is expected that at most one
   * entry will be returned from the search, and that no additional content from
   * the successful search result (e.g., diagnostic message or response
   * controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  searchRequest  The search request to be processed.  If it is
   *                        configured with a search result listener or a size
   *                        limit other than one, then the provided request will
   *                        be duplicated with the appropriate settings.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResultEntry searchForEntry(final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    final SearchRequest r;
    if ((searchRequest.getSearchResultListener() != null) ||
        (searchRequest.getSizeLimit() != 1))
    {
      r = new SearchRequest(searchRequest.getBaseDN(), searchRequest.getScope(),
           searchRequest.getDereferencePolicy(), 1,
           searchRequest.getTimeLimitSeconds(), searchRequest.typesOnly(),
           searchRequest.getFilter(), searchRequest.getAttributes());

      r.setFollowReferrals(searchRequest.followReferralsInternal());
      r.setResponseTimeoutMillis(searchRequest.getResponseTimeoutMillis(null));

      if (searchRequest.hasControl())
      {
        r.setControlsInternal(searchRequest.getControls());
      }
    }
    else
    {
      r = searchRequest;
    }

    final SearchResult result;
    try
    {
      result = search(r);
    }
    catch (final LDAPSearchException lse)
    {
      debugException(lse);

      if (lse.getResultCode() == ResultCode.NO_SUCH_OBJECT)
      {
        return null;
      }

      throw lse;
    }

    if (result.getEntryCount() == 0)
    {
      return null;
    }
    else
    {
      return result.getSearchEntries().get(0);
    }
  }



  /**
   * Processes the provided search request.  It is expected that at most one
   * entry will be returned from the search, and that no additional content from
   * the successful search result (e.g., diagnostic message or response
   * controls) are needed.
   * <BR><BR>
   * Note that if the search does not complete successfully, an
   * {@code LDAPSearchException} will be thrown  In some cases, one or more
   * search result entries or references may have been returned before the
   * failure response is received.  In this case, the
   * {@code LDAPSearchException} methods like {@code getEntryCount},
   * {@code getSearchEntries}, {@code getReferenceCount}, and
   * {@code getSearchReferences} may be used to obtain information about those
   * entries and references.
   *
   * @param  searchRequest  The search request to be processed.  If it is
   *                        configured with a search result listener or a size
   *                        limit other than one, then the provided request will
   *                        be duplicated with the appropriate settings.
   *
   * @return  The entry that was returned from the search, or {@code null} if no
   *          entry was returned or the base entry does not exist.
   *
   * @throws  LDAPSearchException  If the search does not complete successfully,
   *                               if more than a single entry is returned, or
   *                               if a problem is encountered while parsing the
   *                               provided filter string, sending the request,
   *                               or reading the response.  If one or more
   *                               entries or references were returned before
   *                               the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  public SearchResultEntry searchForEntry(
                                final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return searchForEntry((SearchRequest) searchRequest);
  }



  /**
   * Processes the provided search request as an asynchronous operation.
   *
   * @param  searchRequest  The search request to be processed.  It must not be
   *                        {@code null}, and it must be configured with a
   *                        search result listener that is also an
   *                        {@code AsyncSearchResultListener}.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If the provided search request does not have a
   *                         search result listener that is an
   *                         {@code AsyncSearchResultListener}, or if a problem
   *                         occurs while sending the request.
   */
  public AsyncRequestID asyncSearch(final SearchRequest searchRequest)
         throws LDAPException
  {
    ensureNotNull(searchRequest);

    final SearchResultListener searchListener =
         searchRequest.getSearchResultListener();
    if (searchListener == null)
    {
      final LDAPException le = new LDAPException(ResultCode.PARAM_ERROR,
           ERR_ASYNC_SEARCH_NO_LISTENER.get());
      debugCodingError(le);
      throw le;
    }
    else if (! (searchListener instanceof AsyncSearchResultListener))
    {
      final LDAPException le = new LDAPException(ResultCode.PARAM_ERROR,
           ERR_ASYNC_SEARCH_INVALID_LISTENER.get());
      debugCodingError(le);
      throw le;
    }

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return searchRequest.processAsync(this,
         (AsyncSearchResultListener) searchListener);
  }



  /**
   * Processes the provided search request as an asynchronous operation.
   *
   * @param  searchRequest  The search request to be processed.  It must not be
   *                        {@code null}, and it must be configured with a
   *                        search result listener that is also an
   *                        {@code AsyncSearchResultListener}.
   *
   * @return  An async request ID that may be used to reference the operation.
   *
   * @throws  LDAPException  If the provided search request does not have a
   *                         search result listener that is an
   *                         {@code AsyncSearchResultListener}, or if a problem
   *                         occurs while sending the request.
   */
  public AsyncRequestID asyncSearch(final ReadOnlySearchRequest searchRequest)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncSearch((SearchRequest) searchRequest);
  }



  /**
   * Processes the provided generic request and returns the result.  This may
   * be useful for cases in which it is not known what type of operation the
   * request represents.
   *
   * @param  request  The request to be processed.
   *
   * @return  The result obtained from processing the request.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.  Note simply having a
   *                         non-success result code in the response will not
   *                         cause an exception to be thrown.
   */
  public LDAPResult processOperation(final LDAPRequest request)
         throws LDAPException
  {
    return request.process(this, 1);
  }



  /**
   * Retrieves the referral connector that should be used to establish
   * connections for use when following referrals.
   *
   * @return  The referral connector that should be used to establish
   *          connections for use when following referrals.
   */
  public ReferralConnector getReferralConnector()
  {
    if (referralConnector == null)
    {
      return this;
    }
    else
    {
      return referralConnector;
    }
  }



  /**
   * Specifies the referral connector that should be used to establish
   * connections for use when following referrals.
   *
   * @param  referralConnector  The referral connector that should be used to
   *                            establish connections for use when following
   *                            referrals.
   */
  public void setReferralConnector(final ReferralConnector referralConnector)
  {
    if (referralConnector == null)
    {
      this.referralConnector = this;
    }
    else
    {
      this.referralConnector = referralConnector;
    }
  }



  /**
   * Sends the provided LDAP message to the server over this connection.
   *
   * @param  message  The LDAP message to send to the target server.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  void sendMessage(final LDAPMessage message)
         throws LDAPException
  {
    if (needsReconnect.compareAndSet(true, false))
    {
      reconnect();
    }

    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
                              ERR_CONN_NOT_ESTABLISHED.get());
    }
    else
    {
      internals.sendMessage(message, connectionOptions.autoReconnect());
      lastCommunicationTime = System.currentTimeMillis();
    }
  }



  /**
   * Retrieves the message ID that should be used for the next request sent
   * over this connection.
   *
   * @return  The message ID that should be used for the next request sent over
   *          this connection, or -1 if this connection is not established.
   */
  int nextMessageID()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      return -1;
    }
    else
    {
      return internals.nextMessageID();
    }
  }



  /**
   * Retrieves the disconnect info object for this connection, if available.
   *
   * @return  The disconnect info for this connection, or {@code null} if none
   *          is set.
   */
  DisconnectInfo getDisconnectInfo()
  {
    return disconnectInfo.get();
  }



  /**
   * Sets the disconnect type, message, and cause for this connection, if those
   * values have not been previously set.  It will not overwrite any values that
   * had been previously set.
   * <BR><BR>
   * This method may be called by code which is not part of the LDAP SDK to
   * provide additional information about the reason for the closure.  In that
   * case, this method must be called before the call to
   * {@link LDAPConnection#close}.
   *
   * @param  type     The disconnect type.  It must not be {@code null}.
   * @param  message  A message providing additional information about the
   *                  disconnect.  It may be {@code null} if no message is
   *                  available.
   * @param  cause    The exception that was caught to trigger the disconnect.
   *                  It may be {@code null} if the disconnect was not triggered
   *                  by an exception.
   */
  public void setDisconnectInfo(final DisconnectType type, final String message,
                                final Throwable cause)
  {
    disconnectInfo.compareAndSet(null,
         new DisconnectInfo(this, type, message, cause));
  }



  /**
   * Sets the disconnect info for this connection, if it is not already set.
   *
   * @param  info  The disconnect info to be set, if it is not already set.
   *
   * @return  The disconnect info set for the connection, whether it was
   *          previously or newly set.
   */
  DisconnectInfo setDisconnectInfo(final DisconnectInfo info)
  {
    disconnectInfo.compareAndSet(null, info);
    return disconnectInfo.get();
  }



  /**
   * Retrieves the disconnect type for this connection, if available.
   *
   * @return  The disconnect type for this connection, or {@code null} if no
   *          disconnect type has been set.
   */
  public DisconnectType getDisconnectType()
  {
    final DisconnectInfo di = disconnectInfo.get();
    if (di == null)
    {
      return null;
    }
    else
    {
      return di.getType();
    }
  }



  /**
   * Retrieves the disconnect message for this connection, which may provide
   * additional information about the reason for the disconnect, if available.
   *
   * @return  The disconnect message for this connection, or {@code null} if
   *          no disconnect message has been set.
   */
  public String getDisconnectMessage()
  {
    final DisconnectInfo di = disconnectInfo.get();
    if (di == null)
    {
      return null;
    }
    else
    {
      return di.getMessage();
    }
  }



  /**
   * Retrieves the disconnect cause for this connection, which is an exception
   * or error that triggered the connection termination, if available.
   *
   * @return  The disconnect cause for this connection, or {@code null} if no
   *          disconnect cause has been set.
   */
  public Throwable getDisconnectCause()
  {
    final DisconnectInfo di = disconnectInfo.get();
    if (di == null)
    {
      return null;
    }
    else
    {
      return di.getCause();
    }
  }



  /**
   * Indicates that this connection has been closed and is no longer available
   * for use.
   */
  void setClosed()
  {
    needsReconnect.set(false);

    if (disconnectInfo.get() == null)
    {
      try
      {
        final StackTraceElement[] stackElements =
             Thread.currentThread().getStackTrace();
        final StackTraceElement[] parentStackElements =
             new StackTraceElement[stackElements.length - 1];
        System.arraycopy(stackElements, 1, parentStackElements, 0,
             parentStackElements.length);

        setDisconnectInfo(DisconnectType.OTHER,
             ERR_CONN_CLOSED_BY_UNEXPECTED_CALL_PATH.get(
                  getStackTrace(parentStackElements)),
             null);
      }
      catch (final Exception e)
      {
        debugException(e);
      }
    }

    connectionStatistics.incrementNumDisconnects();
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals != null)
    {
      internals.close();
      connectionInternals = null;
    }

    cachedSchema = null;
    lastCommunicationTime = -1L;

    synchronized (this)
    {
      final Timer t = timer;
      timer = null;

      if (t != null)
      {
        t.cancel();
      }
    }
  }



  /**
   * Registers the provided response acceptor with the connection reader.
   *
   * @param  messageID         The message ID for which the acceptor is to be
   *                           registered.
   * @param  responseAcceptor  The response acceptor to register.
   *
   * @throws  LDAPException  If another message acceptor is already registered
   *                         with the provided message ID.
   */
  void registerResponseAcceptor(final int messageID,
                                final ResponseAcceptor responseAcceptor)
       throws LDAPException
  {
    if (needsReconnect.compareAndSet(true, false))
    {
      reconnect();
    }

    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
                              ERR_CONN_NOT_ESTABLISHED.get());
    }
    else
    {
      internals.registerResponseAcceptor(messageID, responseAcceptor);
    }
  }



  /**
   * Deregisters the response acceptor associated with the provided message ID.
   *
   * @param  messageID  The message ID for which to deregister the associated
   *                    response acceptor.
   */
  void deregisterResponseAcceptor(final int messageID)
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals != null)
    {
      internals.deregisterResponseAcceptor(messageID);
    }
  }



  /**
   * Retrieves a timer for use with this connection, creating one if necessary.
   *
   * @return  A timer for use with this connection.
   */
  synchronized Timer getTimer()
  {
    if (timer == null)
    {
      timer = new Timer("Timer thread for " + toString(), true);
    }

    return timer;
  }



  /**
   * {@inheritDoc}
   */
  public LDAPConnection getReferralConnection(final LDAPURL referralURL,
                                              final LDAPConnection connection)
         throws LDAPException
  {
    final String host = referralURL.getHost();
    final int    port = referralURL.getPort();

    BindRequest bindRequest = null;
    if (connection.lastBindRequest != null)
    {
      bindRequest = connection.lastBindRequest.getRebindRequest(host, port);
      if (bindRequest == null)
      {
        throw new LDAPException(ResultCode.REFERRAL,
                                ERR_CONN_CANNOT_AUTHENTICATE_FOR_REFERRAL.get(
                                     host, port));
      }
    }

    final ExtendedRequest connStartTLSRequest = connection.startTLSRequest;

    final LDAPConnection conn = new LDAPConnection(connection.socketFactory,
         connection.connectionOptions, host, port);

    if (connStartTLSRequest != null)
    {
      try
      {
        final ExtendedResult startTLSResult =
             conn.processExtendedOperation(connStartTLSRequest);
        if (startTLSResult.getResultCode() != ResultCode.SUCCESS)
        {
          throw new LDAPException(startTLSResult);
        }
      }
      catch (final LDAPException le)
      {
        debugException(le);
        conn.setDisconnectInfo(DisconnectType.SECURITY_PROBLEM, null, le);
        conn.close();

        throw le;
      }
    }

    if (bindRequest != null)
    {
      try
      {
        conn.bind(bindRequest);
      }
      catch (final LDAPException le)
      {
        debugException(le);
        conn.setDisconnectInfo(DisconnectType.BIND_FAILED, null, le);
        conn.close();

        throw le;
      }
    }

    return conn;
  }



  /**
   * Retrieves the last successful bind request processed on this connection.
   *
   * @return  The last successful bind request processed on this connection.  It
   *          may be {@code null} if no bind has been performed, or if the last
   *          bind attempt was not successful.
   */
  public BindRequest getLastBindRequest()
  {
    return lastBindRequest;
  }



  /**
   * Retrieves the StartTLS request used to secure this connection.
   *
   * @return  The StartTLS request used to secure this connection, or
   *          {@code null} if StartTLS has not been used to secure this
   *          connection.
   */
  public ExtendedRequest getStartTLSRequest()
  {
    return startTLSRequest;
  }



  /**
   * Retrieves an instance of the {@code LDAPConnectionInternals} object for
   * this connection.
   *
   * @param  throwIfDisconnected  Indicates whether to throw an
   *                              {@code LDAPException} if the connection is not
   *                              established.
   *
   * @return  The {@code LDAPConnectionInternals} object for this connection, or
   *          {@code null} if the connection is not established and no exception
   *          should be thrown.
   *
   * @throws  LDAPException  If the connection is not established and
   *                         {@code throwIfDisconnected} is {@code true}.
   */
  LDAPConnectionInternals getConnectionInternals(
                               final boolean throwIfDisconnected)
       throws LDAPException
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if ((internals == null) && throwIfDisconnected)
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_CONN_NOT_ESTABLISHED.get());
    }
    else
    {
      return internals;
    }
  }



  /**
   * Retrieves the cached schema for this connection, if applicable.
   *
   * @return  The cached schema for this connection, or {@code null} if it is
   *          not available (e.g., because the connection is not established,
   *          because {@link LDAPConnectionOptions#useSchema()} is false, or
   *          because an error occurred when trying to read the server schema).
   */
  Schema getCachedSchema()
  {
    return cachedSchema;
  }



  /**
   * Sets the cached schema for this connection.
   *
   * @param  cachedSchema  The cached schema for this connection.  It may be
   *                       {@code null} if no cached schema is available.
   */
  void setCachedSchema(final Schema cachedSchema)
  {
    this.cachedSchema = cachedSchema;
  }



  /**
   * Indicates whether this connection is operating in synchronous mode.
   *
   * @return  {@code true} if this connection is operating in synchronous mode,
   *          or {@code false} if not.
   */
  public boolean synchronousMode()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      return false;
    }
    else
    {
      return internals.synchronousMode();
    }
  }



  /**
   * Reads a response from the server, blocking if necessary until the response
   * has been received.  This should only be used for connections operating in
   * synchronous mode.
   *
   * @param  messageID  The message ID for the response to be read.  Any
   *                    response read with a different message ID will be
   *                    discarded, unless it is an unsolicited notification in
   *                    which case it will be provided to any registered
   *                    unsolicited notification handler.
   *
   * @return  The response read from the server.
   *
   * @throws  LDAPException  If a problem occurs while reading the response.
   */
  LDAPResponse readResponse(final int messageID)
               throws LDAPException
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals != null)
    {
      final LDAPResponse response =
           internals.getConnectionReader().readResponse(messageID);
      debugLDAPResult(response, this);
      return response;
    }
    else
    {
      final DisconnectInfo di = disconnectInfo.get();
      if (di == null)
      {
        return new ConnectionClosedResponse(ResultCode.CONNECT_ERROR,
             ERR_CONN_READ_RESPONSE_NOT_ESTABLISHED.get());
      }
      else
      {
        return new ConnectionClosedResponse(di.getType().getResultCode(),
             di.getMessage());
      }
    }
  }



  /**
   * Retrieves the time that this connection was established in the number of
   * milliseconds since January 1, 1970 UTC (the same format used by
   * {@code System.currentTimeMillis}.
   *
   * @return  The time that this connection was established, or -1 if the
   *          connection is not currently established.
   */
  public long getConnectTime()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals != null)
    {
      return internals.getConnectTime();
    }
    else
    {
      return -1L;
    }
  }



  /**
   * Retrieves the time that this connection was last used to send or receive an
   * LDAP message.  The value will represent the number of milliseconds since
   * January 1, 1970 UTC (the same format used by
   * {@code System.currentTimeMillis}.
   *
   * @return  The time that this connection was last used to send or receive an
   *          LDAP message.  If the connection is not established, then -1 will
   *          be returned.  If the connection is established but no
   *          communication has been performed over the connection since it was
   *          established, then the value of {@link #getConnectTime()} will be
   *          returned.
   */
  public long getLastCommunicationTime()
  {
    if (lastCommunicationTime > 0L)
    {
      return lastCommunicationTime;
    }
    else
    {
      return getConnectTime();
    }
  }



  /**
   * Updates the last communication time for this connection to be the current
   * time.
   */
  void setLastCommunicationTime()
  {
    lastCommunicationTime = System.currentTimeMillis();
  }



  /**
   * Retrieves the connection statistics for this LDAP connection.
   *
   * @return  The connection statistics for this LDAP connection.
   */
  public LDAPConnectionStatistics getConnectionStatistics()
  {
    return connectionStatistics;
  }



  /**
   * Retrieves the number of outstanding operations on this LDAP connection
   * (i.e., the number of operations currently in progress).  The value will
   * only be valid for connections not configured to use synchronous mode.
   *
   * @return  The number of outstanding operations on this LDAP connection, or
   *          -1 if it cannot be determined (e.g., because the connection is not
   *          established or is operating in synchronous mode).
   */
  public int getActiveOperationCount()
  {
    final LDAPConnectionInternals internals = connectionInternals;

    if (internals == null)
    {
      return -1;
    }
    else
    {
      if (internals.synchronousMode())
      {
        return -1;
      }
      else
      {
        return internals.getConnectionReader().getActiveOperationCount();
      }
    }
  }



  /**
   * Retrieves the schema from the provided connection.  If the retrieved schema
   * matches schema that's already in use by other connections, the common
   * schema will be used instead of the newly-retrieved version.
   *
   * @param  c  The connection for which to retrieve the schema.
   *
   * @return  The schema retrieved from the given connection, or a cached
   *          schema if it matched a schema that was already in use.
   *
   * @throws  LDAPException  If a problem is encountered while retrieving or
   *                         parsing the schema.
   */
  private static Schema getCachedSchema(final LDAPConnection c)
         throws LDAPException
  {
    final Schema s = c.getSchema();

    synchronized (SCHEMA_SET)
    {
      return SCHEMA_SET.addAndGet(s);
    }
  }



  /**
   * Retrieves the connection attachment with the specified name.
   *
   * @param  name  The name of the attachment to retrieve.  It must not be
   *               {@code null}.
   *
   * @return  The connection attachment with the specified name, or {@code null}
   *          if there is no such attachment.
   */
  synchronized Object getAttachment(final String name)
  {
    if (attachments == null)
    {
      return null;
    }
    else
    {
      return attachments.get(name);
    }
  }



  /**
   * Sets a connection attachment with the specified name and value.
   *
   * @param  name   The name of the attachment to set.  It must not be
   *                {@code null}.
   * @param  value  The value to use for the attachment.  It may be {@code null}
   *                if an attachment with the specified name should be cleared
   *                rather than overwritten.
   */
  synchronized void setAttachment(final String name, final Object value)
  {
    if (attachments == null)
    {
      attachments = new HashMap<String,Object>(10);
    }

    if (value == null)
    {
      attachments.remove(name);
    }
    else
    {
      attachments.put(name, value);
    }
  }



  /**
   * Performs any necessary cleanup to ensure that this connection is properly
   * closed before it is garbage collected.
   *
   * @throws  Throwable  If the superclass finalizer throws an exception.
   */
  @Override()
  protected void finalize()
            throws Throwable
  {
    super.finalize();

    setDisconnectInfo(DisconnectType.CLOSED_BY_FINALIZER, null, null);
    setClosed();
  }



  /**
   * Retrieves a string representation of this LDAP connection.
   *
   * @return  A string representation of this LDAP connection.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this LDAP connection to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append a string representation of
   *                 this LDAP connection.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPConnection(");

    final String name     = connectionName;
    final String poolName = connectionPoolName;
    if (name != null)
    {
      buffer.append("name='");
      buffer.append(name);
      buffer.append("', ");
    }
    else if (poolName != null)
    {
      buffer.append("poolName='");
      buffer.append(poolName);
      buffer.append("', ");
    }

    final LDAPConnectionInternals internals = connectionInternals;
    if ((internals != null) && internals.isConnected())
    {
      buffer.append("connected to ");
      buffer.append(internals.getHost());
      buffer.append(':');
      buffer.append(internals.getPort());
    }
    else
    {
      buffer.append("not connected");
    }

    buffer.append(')');
  }
}
