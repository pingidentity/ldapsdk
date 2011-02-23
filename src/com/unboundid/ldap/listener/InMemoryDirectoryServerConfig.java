/*
 * Copyright 2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011 UnboundID Corp.
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
package com.unboundid.ldap.listener;



import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Handler;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Mutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides a simple data structure with information that may be
 * used to control the behavior of an in-memory directory server instance.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class InMemoryDirectoryServerConfig
{
  // The base DNs to use for the LDAP listener.
  private DN[] baseDNs;

  // The log handler that should be used to record access log messages about
  // operations processed by the server.
  private Handler accessLogHandler;

  // The address on which to listen for client connections.
  private InetAddress listenAddress;

  // The port on which to listen for client connections.
  private int listenPort;

  // The exception handler that should be used for the listener.
  private LDAPListenerExceptionHandler exceptionHandler;

  // A set of additional credentials that can be used for binding without
  // requiring a corresponding entry in the data set.
  private final Map<DN,byte[]> additionalBindCredentials;

  // The schema to use for the server.
  private Schema schema;

  // The server socket factory to use for the listener.
  private ServerSocketFactory serverSocketFactory;

  // The client socket factory to use for the listener.
  private SocketFactory clientSocketFactory;



  /**
   * Creates a new in-memory directory server config object with the provided
   * set of base DNs.
   *
   * @param  baseDNs  The set of base DNs to use for the server.  It must not
   *                  be {@code null} or empty.
   *
   * @throws  LDAPException  If the provided set of base DN strings is null or
   *                         empty, or if any of the provided base DN strings
   *                         cannot be parsed as a valid DN.
   */
  public InMemoryDirectoryServerConfig(final String... baseDNs)
         throws LDAPException
  {
    this(InMemoryRequestHandler.parseDNs(baseDNs));
  }



  /**
   * Creates a new in-memory directory server config object with the default
   * settings.
   *
   * @param  baseDNs  The set of base DNs to use for the server.  It must not
   *                  be {@code null} or empty.
   *
   * @throws  LDAPException  If the provided set of base DNs is null or empty.
   */
  public InMemoryDirectoryServerConfig(final DN... baseDNs)
         throws LDAPException
  {
    if ((baseDNs == null) || (baseDNs.length == 0))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_NO_BASE_DNS.get());
    }

    this.baseDNs = baseDNs;

    additionalBindCredentials = new LinkedHashMap<DN,byte[]>(1);
    accessLogHandler          = null;
    listenAddress             = null;
    listenPort                = 0;
    exceptionHandler          = null;
    schema                    = null;
    serverSocketFactory       = null;
    clientSocketFactory       = null;
  }



  /**
   * Retrieves the set of base DNs that should be used for the directory server.
   *
   * @return  The set of base DNs that should be used for the directory server.
   */
  public DN[] getBaseDNs()
  {
    return baseDNs;
  }



  /**
   * Specifies the set of base DNs that should be used for the directory server.
   *
   * @param  baseDNs  The set of base DNs that should be used for the directory
   *                  server.  It must not be {@code null} or empty.
   *
   * @throws  LDAPException  If the provided set of base DN strings is null or
   *                         empty, or if any of the provided base DN strings
   *                         cannot be parsed as a valid DN.
   */
  public void setBaseDNs(final String... baseDNs)
         throws LDAPException
  {
    setBaseDNs(InMemoryRequestHandler.parseDNs(baseDNs));
  }



  /**
   * Specifies the set of base DNs that should be used for the directory server.
   *
   * @param  baseDNs  The set of base DNs that should be used for the directory
   *                  server.  It must not be {@code null} or empty.
   *
   * @throws  LDAPException  If the provided set of base DNs is null or empty.
   */
  public void setBaseDNs(final DN... baseDNs)
         throws LDAPException
  {
    if ((baseDNs == null) || (baseDNs.length == 0))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_NO_BASE_DNS.get());
    }

    this.baseDNs = baseDNs;
  }



  /**
   * Retrieves a map containing DNs and passwords of additional users that will
   * be allowed to bind to the server, even if their entries do not exist in the
   * data set.  This can be used to mimic the functionality of special
   * administrative accounts (e.g., "cn=Directory Manager" in many directories).
   * The map that is returned may be altered if desired.
   *
   * @return  A map containing DNs and passwords of additional users that will
   *          be allowed to bind to the server, even if their entries do not
   *          exist in the data set.
   */
  public Map<DN,byte[]> getAdditionalBindCredentials()
  {
    return additionalBindCredentials;
  }



  /**
   * Adds an additional bind DN and password combination that can be used to
   * bind to the server, even if the corresponding entry does not exist in the
   * data set.  This can be used to mimic the functionality of special
   * administrative accounts (e.g., "cn=Directory Manager" in many directories).
   * If a password has already been defined for the given DN, then it will be
   * replaced with the newly-supplied password.
   *
   * @param  dn        The bind DN to allow.  It must not be {@code null} or
   *                   represent the null DN.
   * @param  password  The password for the provided bind DN.  It must not be
   *                   {@code null} or empty.
   *
   * @throws  LDAPException  If there is a problem with the provided bind DN or
   *                         password.
   */
  public void addAdditionalBindCredentials(final String dn,
                                           final String password)
         throws LDAPException
  {
    addAdditionalBindCredentials(dn, StaticUtils.getBytes(password));
  }



  /**
   * Adds an additional bind DN and password combination that can be used to
   * bind to the server, even if the corresponding entry does not exist in the
   * data set.  This can be used to mimic the functionality of special
   * administrative accounts (e.g., "cn=Directory Manager" in many directories).
   * If a password has already been defined for the given DN, then it will be
   * replaced with the newly-supplied password.
   *
   * @param  dn        The bind DN to allow.  It must not be {@code null} or
   *                   represent the null DN.
   * @param  password  The password for the provided bind DN.  It must not be
   *                   {@code null} or empty.
   *
   * @throws  LDAPException  If there is a problem with the provided bind DN or
   *                         password.
   */
  public void addAdditionalBindCredentials(final String dn,
                                           final byte[] password)
         throws LDAPException
  {
    if (dn == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_NULL_ADDITIONAL_BIND_DN.get());
    }

    final DN parsedDN = new DN(dn);
    if (parsedDN.isNullDN())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_NULL_ADDITIONAL_BIND_DN.get());
    }

    if ((password == null) || (password.length == 0))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_NULL_ADDITIONAL_BIND_PW.get());
    }

    additionalBindCredentials.put(parsedDN, password);
  }



  /**
   * Retrieves the port on which the server should listen for client
   * connections, if defined.
   *
   * @return  The port on which the server should listen for client connections,
   *          or zero to indicate that the server should select a port from the
   *          set of free ports available on the system.
   */
  public int getListenPort()
  {
    return listenPort;
  }



  /**
   * Specifies the port on which the server should listen for client
   * connections.  The specified port must be between 1 and 65535 in order to
   * attempt to listen on that specific port, or it may be 0 to indicate that
   * the server should attempt to automatically select an available port that
   * is suitable for use.
   *
   * @param  listenPort  The port on which the server should listen for client
   *                     connections.
   *
   * @throws  LDAPException  If there is a problem with the provided port value.
   */
  public void setListenPort(final int listenPort)
         throws LDAPException
  {
    if ((listenPort < 0) || (listenPort > 65535))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_CFG_INVALID_LISTEN_PORT.get(listenPort));
    }

    this.listenPort = listenPort;
  }



  /**
   * Retrieves the address on which to listen for client connections, if
   * defined.
   *
   * @return  The address on which to listen for client connections, or
   *          {@code null} if the server should listen on all addresses
   *          associated with the system.
   */
  public InetAddress getListenAddress()
  {
    return listenAddress;
  }



  /**
   * Specifies the address on which the server should listen for client
   * connections.
   *
   * @param  listenAddress  The address on which the server should listen for
   *                        client connections.  It may be {@code null} to
   *                        indicate that the server should listen on all
   *                        addresses associated with the system.
   */
  public void setListenAddress(final InetAddress listenAddress)
  {
    this.listenAddress = listenAddress;
  }



  /**
   * Retrieves the object that should be used to handle any errors encountered
   * while attempting to interact with a client, if defined.
   *
   * @return  The object that should be used to handle any errors encountered
   *          while attempting to interact with a client, or {@code null} if no
   *          exception handler should be used.
   */
  public LDAPListenerExceptionHandler getListenerExceptionHandler()
  {
    return exceptionHandler;
  }



  /**
   * Specifies the LDAP listener exception handler that the server should use to
   * handle any errors encountered while attempting to interact with a client.
   *
   * @param  exceptionHandler  The LDAP listener exception handler that the
   *                           server should use to handle any errors
   *                           encountered while attempting to interact with a
   *                           client.  It may be {@code null} if no exception
   *                           handler should be used.
   */
  public void setListenerExceptionHandler(
                   final LDAPListenerExceptionHandler exceptionHandler)
  {
    this.exceptionHandler = exceptionHandler;
  }



  /**
   * Retrieves the schema that should be used by the server, if defined.  If a
   * schema is defined, then it will be used to validate entries and determine
   * which matching rules should be used for various types of matching
   * operations.
   *
   * @return  The schema that should be used by the server, or {@code null} if
   *          no schema should be used.
   */
  public Schema getSchema()
  {
    return schema;
  }



  /**
   * Specifies the schema that should be used by the server.  If a schema is
   * defined, then it will be used to validate entries and determine which
   * matching rules should be used for various types of matching operations.
   *
   * @param  schema  The schema that should be used by the server.  It may be
   *                 {@code null} if no schema should be used.
   */
  public void setSchema(final Schema schema)
  {
    this.schema = schema;
  }



  /**
   * Retrieves the socket factory that should be used by the server in order to
   * accept client connections, if defined.  This may be used to add support for
   * SSL/TLS or other kinds of transformations in the communication between the
   * client and the server.
   *
   * @return  The socket factory that should be used by the server in order to
   *          accept client connections, or {@code null} if a server client
   *          socket factory should be used.
   */
  public ServerSocketFactory getServerSocketFactory()
  {
    return serverSocketFactory;
  }



  /**
   * Specifies the server socket factory that should be used by the server in
   * order to accept client connections.  This may be used to add support for
   * SSL/TLS or other kinds of transformations in the communication between the
   * client and the server.  Note that when using a custom server socket
   * factory, it may also be desirable to provide a custom client socket factory
   * to make it easy to create client connections from the server object.
   *
   * @param  serverSocketFactory  The server socket factory that should be used
   *                              by the server in order to accept client
   *                              connections, or {@code null} if the default
   *                              server socket factory should be used.
   */
  public void setServerSocketFactory(
                   final ServerSocketFactory serverSocketFactory)
  {
    this.serverSocketFactory = serverSocketFactory;
  }



  /**
   * Retrieves the socket factory that should be used to create client
   * connections for communicating with with the server, if defined.  If a
   * custom server socket factory is to be used, then it will likely be
   * necessary to also provide a custom client socket factory to use when
   * creating client connections to the server.
   *
   * @return  The socket factory that should be used to create client
   *          connections for communicating with the server, or {@code null} if
   *          the default client socket factory should be used.
   */
  public SocketFactory getClientSocketFactory()
  {
    return clientSocketFactory;
  }



  /**
   * Specifies the socket factory that should be used to create client
   * connections that may be used for communicating with the server.  If a
   * custom server socket factory is to be used, then it will likely be
   * necessary to also provide a custom client socket factory to use when
   * creating client connections to the server.
   *
   * @param  clientSocketFactory  The socket factory that should be used to
   *                              create client connections for communicating
   *                              with the server, or {@code null} if the
   *                              default client socket factory should be used.
   */
  public void setClientSocketFactory(final SocketFactory clientSocketFactory)
  {
    this.clientSocketFactory = clientSocketFactory;
  }



  /**
   * Retrieves the log handler that should be used to record access log messages
   * about operations processed by the server, if any.
   *
   * @return  The log handler that should be used to record access log messages
   *          about operations processed by the server, or {@code null} if no
   *          access logging should be performed.
   */
  public Handler getAccessLogHandler()
  {
    return accessLogHandler;
  }



  /**
   * Retrieves the log handler that should be used to record access log messages
   * about operations processed by the server.
   *
   * @param  accessLogHandler  The log handler that should be used to record
   *                           access log messages about operations processed by
   *                           the server.  It may be {@code null} if no access
   *                           logging should be performed.
   */
  public void setAccessLogHandler(final Handler accessLogHandler)
  {
    this.accessLogHandler = accessLogHandler;
  }
}
