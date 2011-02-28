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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
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
 * used to control the behavior of an in-memory directory server instance.  At
 * least one base DN must be specified.  For all other properties, the following
 * default values will be used unless an alternate configuration is provided:
 * <UL>
 *   <LI>Listen Address:  The server will listen on all addresses on all
 *       interfaces.</LI>
 *   <LI>Listen Port:  The server will automatically select an available listen
 *       port.</LI>
 *   <LI>Schema:  The server will use a schema with a number of standard
 *       attribute types and object classes.</LI>
 *   <LI>Additional Bind Credentials:  The server will not have any additional
 *       bind credentials.</LI>
 *   <LI>Generate Operational Attributes:  The server will automatically
 *       generate a number of operational attributes.</LI>
 *   <LI>Extended Operation Handlers:  The server will support the password
 *       modify extended operation as defined in RFC 3062 and the "Who Am I?"
 *       extended operation as defined in RFC 4532.</LI>
 *   <LI>SASL Bind Handlers:  The server will support the SASL PLAIN mechanism
 *       as defined in RFC 4616.</LI>
 *   <LI>Access Log Handler:  The server will not perform any access
 *       logging.</LI>
 *   <LI>Listener Exception Handler:  The server will not use a listener
 *       exception handler.</LI>
 *   <LI>Server Socket Factory:  The server will use the JVM-default server
 *       socket factory.</LI>
 *   <LI>Client Socket Factory:  The server will use the JVM-default client
 *       socket factory.</LI>
 * </UL>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class InMemoryDirectoryServerConfig
{
  // Indicates whether to automatically generate operational attributes.
  private boolean generateOperationalAttributes;

  // The base DNs to use for the LDAP listener.
  private DN[] baseDNs;

  // The log handler that should be used to record access log messages about
  // operations processed by the server.
  private Handler accessLogHandler;

  // The address on which to listen for client connections.
  private InetAddress listenAddress;

  // The port on which to listen for client connections.
  private int listenPort;

  // The maximum number of entries to retain in a generated changelog.
  private int maxChangeLogEntries;

  // The exception handler that should be used for the listener.
  private LDAPListenerExceptionHandler exceptionHandler;

  // The extended operation handlers that may be used to process extended
  // operations in the server.
  private final List<InMemoryExtendedOperationHandler>
       extendedOperationHandlers;

  // The SASL bind handlers that may be used to process SASL bind requests in
  // the server.
  private final List<InMemorySASLBindHandler> saslBindHandlers;

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

    additionalBindCredentials     = new LinkedHashMap<DN,byte[]>(1);
    accessLogHandler              = null;
    generateOperationalAttributes = true;
    listenAddress                 = null;
    listenPort                    = 0;
    maxChangeLogEntries           = 0;
    exceptionHandler              = null;
    schema                        = Schema.getDefaultStandardSchema();
    serverSocketFactory           = null;
    clientSocketFactory           = null;

    extendedOperationHandlers =
         new ArrayList<InMemoryExtendedOperationHandler>(2);
    extendedOperationHandlers.add(new PasswordModifyExtendedOperationHandler());
    extendedOperationHandlers.add(new WhoAmIExtendedOperationHandler());

    saslBindHandlers = new ArrayList<InMemorySASLBindHandler>(1);
    saslBindHandlers.add(new PLAINBindHandler());
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



  /**
   * Retrieves a list of the extended operation handlers that may be used to
   * process extended operations in the server.  The contents of the list may
   * be altered by the caller.
   *
   * @return  An updatable list of the extended operation handlers that may be
   *          used to process extended operations in the server.
   */
  public List<InMemoryExtendedOperationHandler> getExtendedOperationHandlers()
  {
    return extendedOperationHandlers;
  }



  /**
   * Adds the provided extended operation handler for use by the server for
   * processing certain types of extended operations.
   *
   * @param  handler  The extended operation handler that should be used by the
   *                  server for processing certain types of extended
   *                  operations.
   */
  public void addExtendedOperationHandler(
                   final InMemoryExtendedOperationHandler handler)
  {
    extendedOperationHandlers.add(handler);
  }



  /**
   * Retrieves a list of the SASL bind handlers that may be used to process
   * SASL bind requests in the server.  The contents of the list may be altered
   * by the caller.
   *
   * @return  An updatable list of the SASL bind handlers that may be used to
   *          process SASL bind requests in the server.
   */
  public List<InMemorySASLBindHandler> getSASLBindHandlers()
  {
    return saslBindHandlers;
  }



  /**
   * Adds the provided SASL bind handler for use by the server for processing
   * certain types of SASL bind requests.
   *
   * @param  handler  The SASL bind handler that should be used by the server
   *                  for processing certain types of SASL bind requests.
   */
  public void addSASLBindHandler(final InMemorySASLBindHandler handler)
  {
    saslBindHandlers.add(handler);
  }



  /**
   * Indicates whether the server should automatically generate operational
   * attributes (including entryDN, entryUUID, creatorsName, createTimestamp,
   * modifiersName, modifyTimestamp, and subschemaSubentry) for entries in the
   * server.
   *
   * @return  {@code true} if the server should automatically generate
   *          operational attributes for entries in the server, or {@code false}
   *          if not.
   */
  public boolean generateOperationalAttributes()
  {
    return generateOperationalAttributes;
  }



  /**
   * Specifies whether the server should automatically generate operational
   * attributes (including entryDN, entryUUID, creatorsName, createTimestamp,
   * modifiersName, modifyTimestamp, and subschemaSubentry) for entries in the
   * server.
   *
   * @param  generateOperationalAttributes  Indicates whether the server should
   *                                        automatically generate operational
   *                                        attributes for entries in the
   *                                        server.
   */
  public void setGenerateOperationalAttributes(
                   final boolean generateOperationalAttributes)
  {
    this.generateOperationalAttributes = generateOperationalAttributes;
  }



  /**
   * Retrieves the maximum number of changelog entries that the server should
   * maintain.
   *
   * @return  The maximum number of changelog entries that the server should
   *          maintain, or 0 if the server should not maintain a changelog.
   */
  public int getMaxChangeLogEntries()
  {
    return maxChangeLogEntries;
  }



  /**
   * Specifies the maximum number of changelog entries that the server should
   * maintain.  A value less than or equal to zero indicates that the server
   * should not attempt to maintain a changelog.
   *
   * @param  maxChangeLogEntries  The maximum number of changelog entries that
   *                              the server should maintain.
   */
  public void setMaxChangeLogEntries(final int maxChangeLogEntries)
  {
    if (maxChangeLogEntries < 0)
    {
      this.maxChangeLogEntries = 0;
    }
    else
    {
      this.maxChangeLogEntries = maxChangeLogEntries;
    }
  }



  /**
   * Retrieves a string representation of this in-memory directory server
   * configuration.
   *
   * @return  A string representation of this in-memory directory server
   *          configuration.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this in-memory directory server
   * configuration to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("InMemoryDirectoryServerConfig(baseDNs={");

    for (int i=0; i < baseDNs.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append('\'');
      baseDNs[i].toString(buffer);
      buffer.append('\'');
    }
    buffer.append('}');

    if (listenAddress != null)
    {
      buffer.append(", listenAddress='");
      buffer.append(listenAddress.getHostAddress());
      buffer.append('\'');
    }

    buffer.append(", listenPort=");
    buffer.append(listenPort);

    buffer.append(", schemaProvided=");
    buffer.append((schema != null));

    if (! additionalBindCredentials.isEmpty())
    {
      buffer.append(", additionalBindDNs={");

      final Iterator<DN> bindDNIterator =
           additionalBindCredentials.keySet().iterator();
      while (bindDNIterator.hasNext())
      {
        buffer.append('\'');
        bindDNIterator.next().toString(buffer);
        buffer.append('\'');
        if (bindDNIterator.hasNext())
        {
          buffer.append(", ");
        }
      }
      buffer.append('}');
    }

    buffer.append(", generateOperationalAttributes=");
    buffer.append(generateOperationalAttributes);

    if (maxChangeLogEntries > 0)
    {
      buffer.append(", maxChangelogEntries=");
      buffer.append(maxChangeLogEntries);
    }

    if (! extendedOperationHandlers.isEmpty())
    {
      buffer.append(", extendedOperationHandlers={");

      final Iterator<InMemoryExtendedOperationHandler>
           handlerIterator = extendedOperationHandlers.iterator();
      while (handlerIterator.hasNext())
      {
        buffer.append(handlerIterator.next().toString());
        if (handlerIterator.hasNext())
        {
          buffer.append(", ");
        }
      }
      buffer.append('}');
    }

    if (! saslBindHandlers.isEmpty())
    {
      buffer.append(", saslBindHandlers={");

      final Iterator<InMemorySASLBindHandler>
           handlerIterator = saslBindHandlers.iterator();
      while (handlerIterator.hasNext())
      {
        buffer.append(handlerIterator.next().toString());
        if (handlerIterator.hasNext())
        {
          buffer.append(", ");
        }
      }
      buffer.append('}');
    }

    if (accessLogHandler != null)
    {
      buffer.append(", accessLogHandlerClass='");
      buffer.append(accessLogHandler.getClass().getName());
      buffer.append('\'');
    }

    if (exceptionHandler != null)
    {
      buffer.append(", listenerExceptionHandlerClass='");
      buffer.append(exceptionHandler.getClass().getName());
      buffer.append('\'');
    }

    if (serverSocketFactory != null)
    {
      buffer.append(", serverSocketFactoryClass='");
      buffer.append(serverSocketFactory.getClass().getName());
      buffer.append('\'');
    }

    if (clientSocketFactory != null)
    {
      buffer.append(", clientSocketFactoryClass='");
      buffer.append(clientSocketFactory.getClass().getName());
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
