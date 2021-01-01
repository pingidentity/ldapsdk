/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.SocketFactory;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.interceptor.
            InMemoryOperationInterceptorRequestHandler;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.BindResponseProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareResponseProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.CompareResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.FullLDAPInterface;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ReadOnlyAddRequest;
import com.unboundid.ldap.sdk.ReadOnlyCompareRequest;
import com.unboundid.ldap.sdk.ReadOnlyDeleteRequest;
import com.unboundid.ldap.sdk.ReadOnlyModifyRequest;
import com.unboundid.ldap.sdk.ReadOnlyModifyDNRequest;
import com.unboundid.ldap.sdk.ReadOnlySearchRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides a utility that may be used to create a simple LDAP server
 * instance that will hold all of its information in memory.  It is intended to
 * be very easy to use, particularly as an embeddable server for testing
 * directory-enabled applications.  It can be easily created, configured,
 * populated, and shut down with only a few lines of code, and it provides a
 * number of convenience methods that can be very helpful in writing test cases
 * that validate the content of the server.
 * <BR><BR>
 * Some notes about the capabilities of this server:
 * <UL>
 *   <LI>It provides reasonably complete support for add, compare, delete,
 *       modify, modify DN (including new superior and subtree move/rename),
 *       search, and unbind operations.</LI>
 *   <LI>It will accept abandon requests, but will not do anything with
 *       them.</LI>
 *   <LI>It provides support for simple bind operations, and for the SASL PLAIN
 *       mechanism.  It also provides an API that can be used to add support for
 *       additional SASL mechanisms.</LI>
 *   <LI>It provides support for the password modify, StartTLS, and "who am I?"
 *       extended operations, as well as an API that can be used to add support
 *       for additional types of extended operations.</LI>
 *   <LI>It provides support for the LDAP assertions, authorization identity,
 *       don't use copy, manage DSA IT, permissive modify, pre-read, post-read,
 *       proxied authorization v1 and v2, server-side sort, simple paged
 *       results, LDAP subentries, subtree delete, and virtual list view request
 *       controls.</LI>
 *   <LI>It supports the use of schema (if provided), but it does not currently
 *       allow updating the schema on the fly.</LI>
 *   <LI>It has the ability to maintain a log of operations processed, as a
 *       simple access log, a more detailed LDAP debug log, or even a log with
 *       generated code that may be used to construct and issue the requests
 *       received by clients.</LI>
 *   <LI>It has the ability to maintain an LDAP-accessible changelog.</LI>
 *   <LI>It provides an option to generate a number of operational attributes,
 *       including entryDN, entryUUID, creatorsName, createTimestamp,
 *       modifiersName, modifyTimestamp, and subschemaSubentry.</LI>
 *   <LI>It provides support for referential integrity, in which case specified
 *       attributes whose values are DNs may be updated if the entries they
 *       reference are deleted or renamed.</LI>
 *   <LI>It provides methods for importing data from and exporting data to LDIF
 *       files, and it has the ability to capture a point-in-time snapshot of
 *       the data (including changelog information) that may be restored at any
 *       point.</LI>
 *   <LI>It implements the {@link FullLDAPInterface} interface, which means that
 *       in many cases it can be used as a drop-in replacement for an
 *       {@link LDAPConnection}.</LI>
 * </UL>
 * <BR><BR>
 * In order to create an in-memory directory server instance, you should first
 * create an {@link InMemoryDirectoryServerConfig} object with the desired
 * settings.  Then use that configuration object to initialize the directory
 * server instance, and call the {@link #startListening} method to start
 * accepting connections from LDAP clients.  The {@link #getConnection} and
 * {@link #getConnectionPool} methods may be used to obtain connections to the
 * server and you can also manually create connections using the information
 * obtained via the {@link #getListenAddress}, {@link #getListenPort}, and
 * {@link #getClientSocketFactory} methods.  When the server is no longer
 * needed, the {@link #shutDown} method should be used to stop the server.  Any
 * number of in-memory directory server instances can be created and running in
 * a single JVM at any time, and many of the methods provided in this class can
 * be used without the server running if operations are to be performed using
 * only method calls rather than via LDAP clients.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process that can be used to create,
 * start, and use an in-memory directory server instance, including support for
 * secure communication using both SSL and StartTLS:
 * <PRE>
 * // Create a base configuration for the server.
 * InMemoryDirectoryServerConfig config =
 *      new InMemoryDirectoryServerConfig("dc=example,dc=com");
 * config.addAdditionalBindCredentials("cn=Directory Manager",
 *      "password");
 *
 * // Update the configuration to support LDAP (with StartTLS) and LDAPS
 * // listeners.
 * final SSLUtil serverSSLUtil = new SSLUtil(
 *      new KeyStoreKeyManager(serverKeyStorePath, serverKeyStorePIN, "JKS",
 *           "server-cert"),
 *      new TrustStoreTrustManager(serverTrustStorePath));
 * final SSLUtil clientSSLUtil = new SSLUtil(
 *      new TrustStoreTrustManager(clientTrustStorePath));
 * config.setListenerConfigs(
 *      InMemoryListenerConfig.createLDAPConfig("LDAP", // Listener name
 *           null, // Listen address. (null = listen on all interfaces)
 *           0, // Listen port (0 = automatically choose an available port)
 *           serverSSLUtil.createSSLSocketFactory()), // StartTLS factory
 *      InMemoryListenerConfig.createLDAPSConfig("LDAPS", // Listener name
 *           null, // Listen address. (null = listen on all interfaces)
 *           0, // Listen port (0 = automatically choose an available port)
 *           serverSSLUtil.createSSLServerSocketFactory(), // Server factory
 *           clientSSLUtil.createSSLSocketFactory())); // Client factory
 *
 * // Create and start the server instance and populate it with an initial set
 * // of data from an LDIF file.
 * InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);
 * server.importFromLDIF(true, ldifFilePath);
 *
 * // Start the server so it will accept client connections.
 * server.startListening();
 *
 * // Get an unencrypted connection to the server's LDAP listener, then use
 * // StartTLS to secure that connection.  Make sure the connection is usable
 * // by retrieving the server root DSE.
 * LDAPConnection connection = server.getConnection("LDAP");
 * connection.processExtendedOperation(new StartTLSExtendedRequest(
 *      clientSSLUtil.createSSLContext()));
 * LDAPTestUtils.assertEntryExists(connection, "");
 * connection.close();
 *
 * // Establish an SSL-based connection to the LDAPS listener, and make sure
 * // that connection is also usable.
 * connection = server.getConnection("LDAPS");
 * LDAPTestUtils.assertEntryExists(connection, "");
 * connection.close();
 *
 * // Shut down the server so that it will no longer accept client
 * // connections, and close all existing connections.
 * server.shutDown(true);
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class InMemoryDirectoryServer
       implements FullLDAPInterface
{
  // The in-memory request handler that will be used for the server.
  @NotNull private final InMemoryRequestHandler inMemoryHandler;

  // The set of listeners that have been configured for this server, mapped by
  // listener name.
  @NotNull private final Map<String,LDAPListener> listeners;

  // The set of configurations for all the LDAP listeners to be used.
  @NotNull private final Map<String,LDAPListenerConfig> ldapListenerConfigs;

  // The set of client socket factories associated with each of the listeners.
  @NotNull private final Map<String,SocketFactory> clientSocketFactories;

  // A read-only representation of the configuration used to create this
  // in-memory directory server.
  @NotNull private final ReadOnlyInMemoryDirectoryServerConfig config;



  /**
   * Creates a very simple instance of an in-memory directory server with the
   * specified set of base DNs.  It will not use a well-defined schema, and will
   * pick a listen port at random.
   *
   * @param  baseDNs  The base DNs to use for the server.  It must not be
   *                  {@code null} or empty.
   *
   * @throws  LDAPException  If a problem occurs while attempting to initialize
   *                         the server.
   */
  public InMemoryDirectoryServer(@NotNull final String... baseDNs)
         throws LDAPException
  {
    this(new InMemoryDirectoryServerConfig(baseDNs));
  }



  /**
   * Creates a new instance of an in-memory directory server with the provided
   * configuration.
   *
   * @param  cfg  The configuration to use for the server.  It must not be
   *              {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while trying to initialize the
   *                         directory server with the provided configuration.
   */
  public InMemoryDirectoryServer(
              @NotNull final InMemoryDirectoryServerConfig cfg)
         throws LDAPException
  {
    Validator.ensureNotNull(cfg);

    config = new ReadOnlyInMemoryDirectoryServerConfig(cfg);
    inMemoryHandler = new InMemoryRequestHandler(config);

    LDAPListenerRequestHandler requestHandler = inMemoryHandler;

    if (config.getAccessLogHandler() != null)
    {
      requestHandler = new AccessLogRequestHandler(config.getAccessLogHandler(),
           requestHandler);
    }

    if (config.getJSONAccessLogHandler() != null)
    {
      requestHandler = new JSONAccessLogRequestHandler(
           config.getJSONAccessLogHandler(), requestHandler);
    }

    if (config.getLDAPDebugLogHandler() != null)
    {
      requestHandler = new LDAPDebuggerRequestHandler(
           config.getLDAPDebugLogHandler(), requestHandler);
    }

    if (config.getCodeLogPath() != null)
    {
      try
      {
        requestHandler = new ToCodeRequestHandler(config.getCodeLogPath(),
             config.includeRequestProcessingInCodeLog(), requestHandler);
      }
      catch (final IOException ioe)
      {
        Debug.debugException(ioe);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MEM_DS_CANNOT_OPEN_CODE_LOG.get(config.getCodeLogPath(),
                  StaticUtils.getExceptionMessage(ioe)),
             ioe);
      }
    }

    if (! config.getOperationInterceptors().isEmpty())
    {
      requestHandler = new InMemoryOperationInterceptorRequestHandler(
           config.getOperationInterceptors(), requestHandler);
    }


    final List<InMemoryListenerConfig> listenerConfigs =
         config.getListenerConfigs();

    listeners = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(listenerConfigs.size()));
    ldapListenerConfigs = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(listenerConfigs.size()));
    clientSocketFactories = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(listenerConfigs.size()));

    for (final InMemoryListenerConfig c : listenerConfigs)
    {
      final String name = StaticUtils.toLowerCase(c.getListenerName());

      final LDAPListenerRequestHandler listenerRequestHandler;
      if (c.getStartTLSSocketFactory() == null)
      {
        listenerRequestHandler =  requestHandler;
      }
      else
      {
        listenerRequestHandler =
             new StartTLSRequestHandler(c.getStartTLSSocketFactory(),
                  requestHandler, c.requestClientCertificate(),
                  c.requireClientCertificate());
      }

      final LDAPListenerConfig listenerCfg = new LDAPListenerConfig(
           c.getListenPort(), listenerRequestHandler);
      listenerCfg.setMaxConnections(config.getMaxConnections());
      listenerCfg.setMaxMessageSizeBytes(config.getMaxMessageSizeBytes());
      listenerCfg.setExceptionHandler(config.getListenerExceptionHandler());
      listenerCfg.setListenAddress(c.getListenAddress());
      listenerCfg.setServerSocketFactory(c.getServerSocketFactory());
      listenerCfg.setRequestClientCertificate(c.requestClientCertificate());
      listenerCfg.setRequireClientCertificate(c.requireClientCertificate());

      ldapListenerConfigs.put(name, listenerCfg);

      if (c.getClientSocketFactory() != null)
      {
        clientSocketFactories.put(name, c.getClientSocketFactory());
      }
    }
  }



  /**
   * Attempts to start listening for client connections on all configured
   * listeners.  Any listeners that are already running will be unaffected.
   *
   * @throws  LDAPException  If a problem occurs while attempting to create any
   *                         of the configured listeners.  Even if an exception
   *                         is thrown, then as many listeners as possible will
   *                         be started.
   */
  public synchronized void startListening()
         throws LDAPException
  {
    final ArrayList<String> messages = new ArrayList<>(listeners.size());

    for (final Map.Entry<String,LDAPListenerConfig> cfgEntry :
         ldapListenerConfigs.entrySet())
    {
      final String name = cfgEntry.getKey();

      if (listeners.containsKey(name))
      {
        // This listener is already running.
        continue;
      }

      final LDAPListenerConfig listenerConfig = cfgEntry.getValue();
      final LDAPListener listener = new LDAPListener(listenerConfig);

      try
      {
        listener.startListening();
        listenerConfig.setListenPort(listener.getListenPort());
        listeners.put(name, listener);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        messages.add(ERR_MEM_DS_START_FAILED.get(name,
             StaticUtils.getExceptionMessage(e)));
      }
    }

    if (! messages.isEmpty())
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           StaticUtils.concatenateStrings(messages));
    }
  }



  /**
   * Attempts to start listening for client connections on the specified
   * listener.  If the listener is already running, then it will be unaffected.
   *
   * @param  listenerName  The name of the listener to be started.  It must not
   *                       be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to start the
   *                         requested listener.
   */
  public synchronized void startListening(@NotNull final String listenerName)
         throws LDAPException
  {
    // If the listener is already running, then there's nothing to do.
    final String name = StaticUtils .toLowerCase(listenerName);
    if (listeners.containsKey(name))
    {
      return;
    }

    // Get the configuration to use for the listener.
    final LDAPListenerConfig listenerConfig = ldapListenerConfigs.get(name);
    if (listenerConfig == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_NO_SUCH_LISTENER.get(listenerName));
    }


    final LDAPListener listener = new LDAPListener(listenerConfig);

    try
    {
      listener.startListening();
      listenerConfig.setListenPort(listener.getListenPort());
      listeners.put(name, listener);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_MEM_DS_START_FAILED.get(name,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void close()
  {
    shutDown(true);
  }



  /**
   * Closes all connections that are currently established to the server.  This
   * has no effect on the ability to accept new connections.
   *
   * @param  sendNoticeOfDisconnection  Indicates whether to send the client a
   *                                    notice of disconnection unsolicited
   *                                    notification before closing the
   *                                    connection.
   */
  public synchronized void closeAllConnections(
                                final boolean sendNoticeOfDisconnection)
  {
    for (final LDAPListener l : listeners.values())
    {
      try
      {
        l.closeAllConnections(sendNoticeOfDisconnection);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }



  /**
   * Shuts down all configured listeners.  Any listeners that are already
   * stopped will be unaffected.
   *
   * @param  closeExistingConnections  Indicates whether to close all existing
   *                                   connections, or merely to stop accepting
   *                                   new connections.
   */
  public synchronized void shutDown(final boolean closeExistingConnections)
  {
    for (final LDAPListener l : listeners.values())
    {
      try
      {
        l.shutDown(closeExistingConnections);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    listeners.clear();
  }



  /**
   * Shuts down the specified listener.  If there is no such listener defined,
   * or if the specified listener is not running, then no action will be taken.
   *
   * @param  listenerName              The name of the listener to be shut down.
   *                                   It must not be {@code null}.
   * @param  closeExistingConnections  Indicates whether to close all existing
   *                                   connections, or merely to stop accepting
   *                                   new connections.
   */
  public synchronized void shutDown(@NotNull final String listenerName,
                                    final boolean closeExistingConnections)
  {
    final String name = StaticUtils.toLowerCase(listenerName);
    final LDAPListener listener = listeners.remove(name);
    if (listener != null)
    {
      listener.shutDown(closeExistingConnections);
    }
  }



  /**
   * Attempts to restart all listeners defined in the server.  All running
   * listeners will be stopped, and all configured listeners will be started.
   *
   * @throws  LDAPException  If a problem occurs while attempting to restart any
   *                         of the listeners.  Even if an exception is thrown,
   *                         as many listeners as possible will be started.
   */
  public synchronized void restartServer()
         throws LDAPException
  {
    shutDown(true);

    try
    {
      Thread.sleep(100L);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }
    }

    startListening();
  }



  /**
   * Attempts to restart the specified listener.  If it is running, it will be
   * stopped.  It will then be started.
   *
   * @param  listenerName  The name of the listener to be restarted.  It must
   *                       not be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to restart the
   *                         specified listener.
   */
  public synchronized void restartListener(@NotNull final String listenerName)
         throws LDAPException
  {
    shutDown(listenerName, true);

    try
    {
      Thread.sleep(100L);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }
    }

    startListening(listenerName);
  }



  /**
   * Retrieves a read-only representation of the configuration used to create
   * this in-memory directory server instance.
   *
   * @return  A read-only representation of the configuration used to create
   *          this in-memory directory server instance.
   */
  @NotNull()
  public ReadOnlyInMemoryDirectoryServerConfig getConfig()
  {
    return config;
  }



  /**
   * Retrieves the in-memory request handler that is used to perform the real
   * server processing.
   *
   * @return  The in-memory request handler that is used to perform the real
   *          server processing.
   */
  @NotNull()
  InMemoryRequestHandler getInMemoryRequestHandler()
  {
    return inMemoryHandler;
  }



  /**
   * Creates a point-in-time snapshot of the information contained in this
   * in-memory directory server instance.  It may be restored using the
   * {@link #restoreSnapshot} method.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @return  The snapshot created based on the current content of this
   *          in-memory directory server instance.
   */
  @NotNull()
  public InMemoryDirectoryServerSnapshot createSnapshot()
  {
    return inMemoryHandler.createSnapshot();
  }



  /**
   * Restores the this in-memory directory server instance to match the content
   * it held at the time the snapshot was created.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  snapshot  The snapshot to be restored.  It must not be
   *                   {@code null}.
   */
  public void restoreSnapshot(
                   @NotNull final InMemoryDirectoryServerSnapshot snapshot)
  {
    inMemoryHandler.restoreSnapshot(snapshot);
  }



  /**
   * Retrieves the list of base DNs configured for use by the server.
   *
   * @return  The list of base DNs configured for use by the server.
   */
  @NotNull()
  public List<DN> getBaseDNs()
  {
    return inMemoryHandler.getBaseDNs();
  }



  /**
   * Attempts to establish a client connection to the server.  If multiple
   * listeners are configured, then it will attempt to establish a connection to
   * the first configured listener that is running.
   *
   * @return  The client connection that has been established.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         create the connection.
   */
  @NotNull()
  public LDAPConnection getConnection()
         throws LDAPException
  {
    return getConnection(null, null);
  }



  /**
   * Attempts to establish a client connection to the server.
   *
   * @param  options  The connection options to use when creating the
   *                  connection.  It may be {@code null} if a default set of
   *                  options should be used.
   *
   * @return  The client connection that has been established.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         create the connection.
   */
  @NotNull()
  public LDAPConnection getConnection(
                             @Nullable final LDAPConnectionOptions options)
         throws LDAPException
  {
    return getConnection(null, options);
  }



  /**
   * Attempts to establish a client connection to the specified listener.
   *
   * @param  listenerName  The name of the listener to which to establish the
   *                       connection.  It may be {@code null} if a connection
   *                       should be established to the first available
   *                       listener.
   *
   * @return  The client connection that has been established.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         create the connection.
   */
  @NotNull()
  public LDAPConnection getConnection(@Nullable final String listenerName)
         throws LDAPException
  {
    return getConnection(listenerName, null);
  }



  /**
   * Attempts to establish a client connection to the specified listener.
   *
   * @param  listenerName  The name of the listener to which to establish the
   *                       connection.  It may be {@code null} if a connection
   *                       should be established to the first available
   *                       listener.
   * @param  options       The set of LDAP connection options to use for the
   *                       connection that is created.
   *
   * @return  The client connection that has been established.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         create the connection.
   */
  @NotNull()
  public synchronized LDAPConnection getConnection(
                           @Nullable final String listenerName,
                           @Nullable final LDAPConnectionOptions options)
         throws LDAPException
  {
    final LDAPListenerConfig listenerConfig;
    final SocketFactory clientSocketFactory;

    if (listenerName == null)
    {
      final String name = getFirstListenerName();
      if (name == null)
      {
        throw new LDAPException(ResultCode.CONNECT_ERROR,
             ERR_MEM_DS_GET_CONNECTION_NO_LISTENERS.get());
      }

      listenerConfig      = ldapListenerConfigs.get(name);
      clientSocketFactory = clientSocketFactories.get(name);
    }
    else
    {
      final String name = StaticUtils.toLowerCase(listenerName);
      if (! listeners.containsKey(name))
      {
        throw new LDAPException(ResultCode.CONNECT_ERROR,
             ERR_MEM_DS_GET_CONNECTION_LISTENER_NOT_RUNNING.get(listenerName));
      }

      listenerConfig      = ldapListenerConfigs.get(name);
      clientSocketFactory = clientSocketFactories.get(name);
    }

    String hostAddress;
    final InetAddress listenAddress = listenerConfig.getListenAddress();
    if ((listenAddress == null) || (listenAddress.isAnyLocalAddress()))
    {
      try
      {
        hostAddress = LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.
             getLocalHost().getHostAddress();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        hostAddress = "127.0.0.1";
      }
    }
    else
    {
      hostAddress = listenAddress.getHostAddress();
    }

    return new LDAPConnection(clientSocketFactory, options, hostAddress,
         listenerConfig.getListenPort());
  }



  /**
   * Attempts to establish a connection pool to the server with the specified
   * maximum number of connections.
   *
   * @param  maxConnections  The maximum number of connections to maintain in
   *                         the connection pool.  It must be greater than or
   *                         equal to one.
   *
   * @return  The connection pool that has been created.
   *
   * @throws  LDAPException  If a problem occurs while attempting to create the
   *                         connection pool.
   */
  @NotNull()
  public LDAPConnectionPool getConnectionPool(final int maxConnections)
         throws LDAPException
  {
    return getConnectionPool(null, null, 1, maxConnections);
  }



  /**
   * Attempts to establish a connection pool to the server with the provided
   * settings.
   *
   * @param  listenerName        The name of the listener to which the
   *                             connections should be established.
   * @param  options             The connection options to use when creating
   *                             connections for use in the pool.  It may be
   *                             {@code null} if a default set of options should
   *                             be used.
   * @param  initialConnections  The initial number of connections to establish
   *                             in the connection pool.  It must be greater
   *                             than or equal to one.
   * @param  maxConnections      The maximum number of connections to maintain
   *                             in the connection pool.  It must be greater
   *                             than or equal to the initial number of
   *                             connections.
   *
   * @return  The connection pool that has been created.
   *
   * @throws  LDAPException  If a problem occurs while attempting to create the
   *                         connection pool.
   */
  @NotNull()
  public LDAPConnectionPool getConnectionPool(
                                 @Nullable final String listenerName,
                                 @Nullable final LDAPConnectionOptions options,
                                 final int initialConnections,
                                 final int maxConnections)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection(listenerName, options);
    return new LDAPConnectionPool(conn, initialConnections, maxConnections);
  }



  /**
   * Retrieves the configured listen address for the first active listener, if
   * defined.
   *
   * @return  The configured listen address for the first active listener, or
   *          {@code null} if that listener does not have an
   *          explicitly-configured listen address or there are no active
   *          listeners.
   */
  @Nullable()
  public InetAddress getListenAddress()
  {
    return getListenAddress(null);
  }



  /**
   * Retrieves the configured listen address for the specified listener, if
   * defined.
   *
   * @param  listenerName  The name of the listener for which to retrieve the
   *                       listen address.  It may be {@code null} in order to
   *                       obtain the listen address for the first active
   *                       listener.
   *
   * @return  The configured listen address for the specified listener, or
   *          {@code null} if there is no such listener or the listener does not
   *          have an explicitly-configured listen address.
   */
  @Nullable()
  public synchronized InetAddress getListenAddress(
                                       @Nullable final String listenerName)
  {
    final String name;
    if (listenerName == null)
    {
      name = getFirstListenerName();
    }
    else
    {
      name = StaticUtils.toLowerCase(listenerName);
    }

    final LDAPListenerConfig listenerCfg = ldapListenerConfigs.get(name);
    if (listenerCfg == null)
    {
      return null;
    }
    else
    {
      return listenerCfg.getListenAddress();
    }
  }



  /**
   * Retrieves the configured listen port for the first active listener.
   *
   * @return  The configured listen port for the first active listener, or -1 if
   *          there are no active listeners.
   */
  public int getListenPort()
  {
    return getListenPort(null);
  }



  /**
   * Retrieves the configured listen port for the specified listener, if
   * available.
   *
   * @param  listenerName  The name of the listener for which to retrieve the
   *                       listen port.  It may be {@code null} in order to
   *                       obtain the listen port for the first active
   *                       listener.
   *
   * @return  The configured listen port for the specified listener, or -1 if
   *          there is no such listener or the listener is not active.
   */
  public synchronized int getListenPort(@Nullable final String listenerName)
  {
    final String name;
    if (listenerName == null)
    {
      name = getFirstListenerName();
    }
    else
    {
      name = StaticUtils.toLowerCase(listenerName);
    }

    final LDAPListener listener = listeners.get(name);
    if (listener == null)
    {
      return -1;
    }
    else
    {
      return listener.getListenPort();
    }
  }



  /**
   * Retrieves the configured client socket factory for the first active
   * listener.
   *
   * @return  The configured client socket factory for the first active
   *          listener, or {@code null} if that listener does not have an
   *          explicitly-configured socket factory or there are no active
   *          listeners.
   */
  @Nullable()
  public SocketFactory getClientSocketFactory()
  {
    return getClientSocketFactory(null);
  }



  /**
   * Retrieves the configured client socket factory for the specified listener,
   * if available.
   *
   * @param  listenerName  The name of the listener for which to retrieve the
   *                       client socket factory.  It may be {@code null} in
   *                       order to obtain the client socket factory for the
   *                       first active listener.
   *
   * @return  The configured client socket factory for the specified listener,
   *          or {@code null} if there is no such listener or that listener does
   *          not have an explicitly-configured client socket factory.
   */
  @Nullable()
  public synchronized SocketFactory getClientSocketFactory(
                                         @Nullable final String listenerName)
  {
    final String name;
    if (listenerName == null)
    {
      name = getFirstListenerName();
    }
    else
    {
      name = StaticUtils.toLowerCase(listenerName);
    }

    return clientSocketFactories.get(name);
  }



  /**
   * Retrieves the name of the first running listener.
   *
   * @return  The name of the first running listener, or {@code null} if there
   *          are no active listeners.
   */
  @Nullable()
  private String getFirstListenerName()
  {
    for (final Map.Entry<String,LDAPListenerConfig> e :
         ldapListenerConfigs.entrySet())
    {
      final String name = e.getKey();
      if (listeners.containsKey(name))
      {
        return name;
      }
    }

    return null;
  }



  /**
   * Retrieves the delay in milliseconds that the server should impose before
   * beginning processing for operations.
   *
   * @return  The delay in milliseconds that the server should impose before
   *          beginning processing for operations, or 0 if there should be no
   *          delay inserted when processing operations.
   */
  public long getProcessingDelayMillis()
  {
    return inMemoryHandler.getProcessingDelayMillis();
  }



  /**
   * Specifies the delay in milliseconds that the server should impose before
   * beginning processing for operations.
   *
   * @param  processingDelayMillis  The delay in milliseconds that the server
   *                                should impose before beginning processing
   *                                for operations.  A value less than or equal
   *                                to zero may be used to indicate that there
   *                                should be no delay.
   */
  public void setProcessingDelayMillis(final long processingDelayMillis)
  {
    inMemoryHandler.setProcessingDelayMillis(processingDelayMillis);
  }



  /**
   * Retrieves the number of entries currently held in the server.  The count
   * returned will not include entries which are part of the changelog.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @return  The number of entries currently held in the server.
   */
  public int countEntries()
  {
    return countEntries(false);
  }



  /**
   * Retrieves the number of entries currently held in the server, optionally
   * including those entries which are part of the changelog.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  includeChangeLog  Indicates whether to include entries that are
   *                           part of the changelog in the count.
   *
   * @return  The number of entries currently held in the server.
   */
  public int countEntries(final boolean includeChangeLog)
  {
    return inMemoryHandler.countEntries(includeChangeLog);
  }



  /**
   * Retrieves the number of entries currently held in the server whose DN
   * matches or is subordinate to the provided base DN.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  baseDN  The base DN to use for the determination.
   *
   * @return  The number of entries currently held in the server whose DN
   *          matches or is subordinate to the provided base DN.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         DN.
   */
  public int countEntriesBelow(@NotNull final String baseDN)
         throws LDAPException
  {
    return inMemoryHandler.countEntriesBelow(baseDN);
  }



  /**
   * Removes all entries currently held in the server.  If a changelog is
   * enabled, then all changelog entries will also be cleared but the base
   * "cn=changelog" entry will be retained.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   */
  public void clear()
  {
    inMemoryHandler.clear();
  }



  /**
   * Reads entries from the specified LDIF file and adds them to the server,
   * optionally clearing any existing entries before beginning to add the new
   * entries.  If an error is encountered while adding entries from LDIF then
   * the server will remain populated with the data it held before the import
   * attempt (even if the {@code clear} is given with a value of {@code true}).
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  clear  Indicates whether to remove all existing entries prior to
   *                adding entries read from LDIF.
   * @param  path   The path to the LDIF file from which the entries should be
   *                read.  It must not be {@code null}.
   *
   * @return  The number of entries read from LDIF and added to the server.
   *
   * @throws  LDAPException  If a problem occurs while reading entries or adding
   *                         them to the server.
   */
  public int importFromLDIF(final boolean clear, @NotNull final String path)
         throws LDAPException
  {
    return importFromLDIF(clear, new File(path));
  }



  /**
   * Reads entries from the specified LDIF file and adds them to the server,
   * optionally clearing any existing entries before beginning to add the new
   * entries.  If an error is encountered while adding entries from LDIF then
   * the server will remain populated with the data it held before the import
   * attempt (even if the {@code clear} is given with a value of {@code true}).
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  clear     Indicates whether to remove all existing entries prior to
   *                   adding entries read from LDIF.
   * @param  ldifFile  The LDIF file from which the entries should be read.  It
   *                   must not be {@code null}.
   *
   * @return  The number of entries read from LDIF and added to the server.
   *
   * @throws  LDAPException  If a problem occurs while reading entries or adding
   *                         them to the server.
   */
  public int importFromLDIF(final boolean clear, @NotNull final File ldifFile)
         throws LDAPException
  {
    final LDIFReader reader;
    try
    {
      reader = new LDIFReader(ldifFile);

      final Schema schema = getSchema();
      if (schema != null)
      {
        reader.setSchema(schema);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_MEM_DS_INIT_FROM_LDIF_CANNOT_CREATE_READER.get(
                ldifFile.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
           e);
    }

    return importFromLDIF(clear, reader);
  }



  /**
   * Reads entries from the provided LDIF reader and adds them to the server,
   * optionally clearing any existing entries before beginning to add the new
   * entries.  If an error is encountered while adding entries from LDIF then
   * the server will remain populated with the data it held before the import
   * attempt (even if the {@code clear} is given with a value of {@code true}).
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  clear   Indicates whether to remove all existing entries prior to
   *                 adding entries read from LDIF.
   * @param  reader  The LDIF reader to use to obtain the entries to be
   *                 imported.
   *
   * @return  The number of entries read from LDIF and added to the server.
   *
   * @throws  LDAPException  If a problem occurs while reading entries or adding
   *                         them to the server.
   */
  public int importFromLDIF(final boolean clear,
                            @NotNull final LDIFReader reader)
         throws LDAPException
  {
    return inMemoryHandler.importFromLDIF(clear, reader);
  }



  /**
   * Writes the current contents of the server in LDIF form to the specified
   * file.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  path                   The path of the file to which the LDIF
   *                                entries should be written.
   * @param  excludeGeneratedAttrs  Indicates whether to exclude automatically
   *                                generated operational attributes like
   *                                entryUUID, entryDN, creatorsName, etc.
   * @param  excludeChangeLog       Indicates whether to exclude entries
   *                                contained in the changelog.
   *
   * @return  The number of entries written to LDIF.
   *
   * @throws  LDAPException  If a problem occurs while writing entries to LDIF.
   */
  public int exportToLDIF(@NotNull final String path,
                          final boolean excludeGeneratedAttrs,
                          final boolean excludeChangeLog)
         throws LDAPException
  {
    final LDIFWriter ldifWriter;
    try
    {
      ldifWriter = new LDIFWriter(path);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_MEM_DS_EXPORT_TO_LDIF_CANNOT_CREATE_WRITER.get(path,
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    return exportToLDIF(ldifWriter, excludeGeneratedAttrs, excludeChangeLog,
         true);
  }



  /**
   * Writes the current contents of the server in LDIF form using the provided
   * LDIF writer.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  ldifWriter             The LDIF writer to use when writing the
   *                                entries.  It must not be {@code null}.
   * @param  excludeGeneratedAttrs  Indicates whether to exclude automatically
   *                                generated operational attributes like
   *                                entryUUID, entryDN, creatorsName, etc.
   * @param  excludeChangeLog       Indicates whether to exclude entries
   *                                contained in the changelog.
   * @param  closeWriter            Indicates whether the LDIF writer should be
   *                                closed after all entries have been written.
   *
   * @return  The number of entries written to LDIF.
   *
   * @throws  LDAPException  If a problem occurs while writing entries to LDIF.
   */
  public int exportToLDIF(@NotNull final LDIFWriter ldifWriter,
                          final boolean excludeGeneratedAttrs,
                          final boolean excludeChangeLog,
                          final boolean closeWriter)
         throws LDAPException
  {
    return inMemoryHandler.exportToLDIF(ldifWriter, excludeGeneratedAttrs,
         excludeChangeLog, closeWriter);
  }



  /**
   * Reads LDIF change records from the specified LDIF file and applies them
   * to the data in the server.  Any LDIF records without a changetype will be
   * treated as add change records.  If an error is encountered while attempting
   * to apply the requested changes, then the server will remain populated with
   * the data it held before this method was called, even if earlier changes
   * could have been applied successfully.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  path   The path to the LDIF file from which the LDIF change
   *                records should be read.  It must not be {@code null}.
   *
   * @return  The number of changes applied from the LDIF file.
   *
   * @throws  LDAPException  If a problem occurs while reading change records
   *                         or applying them to the server.
   */
  public int applyChangesFromLDIF(@NotNull final String path)
         throws LDAPException
  {
    return applyChangesFromLDIF(new File(path));
  }



  /**
   * Reads LDIF change records from the specified LDIF file and applies them
   * to the data in the server.  Any LDIF records without a changetype will be
   * treated as add change records.  If an error is encountered while attempting
   * to apply the requested changes, then the server will remain populated with
   * the data it held before this method was called, even if earlier changes
   * could have been applied successfully.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  ldifFile  The LDIF file from which the LDIF change records should
   *                   be read.  It must not be {@code null}.
   *
   * @return  The number of changes applied from the LDIF file.
   *
   * @throws  LDAPException  If a problem occurs while reading change records
   *                         or applying them to the server.
   */
  public int applyChangesFromLDIF(@NotNull final File ldifFile)
         throws LDAPException
  {
    final LDIFReader reader;
    try
    {
      reader = new LDIFReader(ldifFile);

      final Schema schema = getSchema();
      if (schema != null)
      {
        reader.setSchema(schema);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_MEM_DS_APPLY_CHANGES_FROM_LDIF_CANNOT_CREATE_READER.get(
                ldifFile.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
           e);
    }

    return applyChangesFromLDIF(reader);
  }



  /**
   * Reads LDIF change records from the provided LDIF reader file and applies
   * them to the data in the server.  Any LDIF records without a changetype will
   * be treated as add change records.  If an error is encountered while
   * attempting to apply the requested changes, then the server will remain
   * populated with the data it held before this method was called, even if
   * earlier changes could have been applied successfully.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  reader  The LDIF reader to use to obtain the change records to be
   *                 applied.
   *
   * @return  The number of changes applied from the LDIF file.
   *
   * @throws  LDAPException  If a problem occurs while reading change records
   *                         or applying them to the server.
   */
  public int applyChangesFromLDIF(@NotNull final LDIFReader reader)
         throws LDAPException
  {
    return inMemoryHandler.applyChangesFromLDIF(reader);
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   */
  @Override()
  @Nullable()
  public RootDSE getRootDSE()
         throws LDAPException
  {
    return new RootDSE(inMemoryHandler.getEntry(""));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   */
  @Override()
  @Nullable()
  public Schema getSchema()
         throws LDAPException
  {
    return inMemoryHandler.getSchema();
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   */
  @Override()
  @Nullable()
  public Schema getSchema(@Nullable final String entryDN)
         throws LDAPException
  {
    return inMemoryHandler.getSchema();
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   */
  @Override()
  @Nullable()
  public SearchResultEntry getEntry(@NotNull final String dn)
         throws LDAPException
  {
    return searchForEntry(dn, SearchScope.BASE,
         Filter.createPresenceFilter("objectClass"));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are
   * allowed in the server.
   */
  @Override()
  @Nullable()
  public SearchResultEntry getEntry(@NotNull final String dn,
                                    @Nullable final String... attributes)
         throws LDAPException
  {
    return searchForEntry(dn, SearchScope.BASE,
         Filter.createPresenceFilter("objectClass"), attributes);
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether add operations are allowed in
   * the server.
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final String dn,
                        @NotNull final Attribute... attributes)
         throws LDAPException
  {
    return add(new AddRequest(dn, attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether add operations are allowed in
   * the server.
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final String dn,
                        @NotNull final Collection<Attribute> attributes)
         throws LDAPException
  {
    return add(new AddRequest(dn, attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether add operations are allowed in
   * the server.
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final Entry entry)
         throws LDAPException
  {
    return add(new AddRequest(entry));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether add operations are allowed in
   * the server.
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final String... ldifLines)
         throws LDIFException, LDAPException
  {
    return add(new AddRequest(ldifLines));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether add operations are allowed in
   * the server.
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final AddRequest addRequest)
         throws LDAPException
  {
    return inMemoryHandler.add(addRequest);
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether add operations are allowed in
   * the server.
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final ReadOnlyAddRequest addRequest)
         throws LDAPException
  {
    return add(addRequest.duplicate());
  }



  /**
   * Attempts to add all of the provided entries to the server.  If a problem is
   * encountered while attempting to add any of the provided entries, then the
   * server will remain populated with the data it held before this method was
   * called.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether add operations are allowed in
   * the server.
   *
   * @param  entries  The entries to be added to the server.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to add
   *                         any of the provided entries.
   */
  public void addEntries(@NotNull final Entry... entries)
         throws LDAPException
  {
    addEntries(Arrays.asList(entries));
  }



  /**
   * Attempts to add all of the provided entries to the server.  If a problem is
   * encountered while attempting to add any of the provided entries, then the
   * server will remain populated with the data it held before this method was
   * called.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether add operations are allowed in
   * the server.
   *
   * @param  entries  The entries to be added to the server.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to add
   *                         any of the provided entries.
   */
  public void addEntries(@NotNull final List<? extends Entry> entries)
         throws LDAPException
  {
    inMemoryHandler.addEntries(entries);
  }



  /**
   * Attempts to add a set of entries provided in LDIF form in which each
   * element of the provided array is a line of the LDIF representation, with
   * empty strings as separators between entries (as you would have for blank
   * lines in an LDIF file).  If a problem is encountered while attempting to
   * add any of the provided entries, then the server will remain populated with
   * the data it held before this method was called.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether add operations are allowed in
   * the server.
   *
   * @param  ldifEntryLines  The lines comprising the LDIF representation of the
   *                         entries to be added.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to add
   *                         any of the provided entries.
   */
  public void addEntries(@NotNull final String... ldifEntryLines)
         throws LDAPException
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    for (final String line : ldifEntryLines)
    {
      buffer.append(line);
      buffer.append(StaticUtils.EOL_BYTES);
    }

    final ArrayList<Entry> entryList = new ArrayList<>(10);
    final LDIFReader reader = new LDIFReader(buffer.asInputStream());

    final Schema schema = getSchema();
    if (schema != null)
    {
      reader.setSchema(schema);
    }

    while (true)
    {
      try
      {
        final Entry entry = reader.readEntry();
        if (entry == null)
        {
          break;
        }
        else
        {
          entryList.add(entry);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MEM_DS_ADD_ENTRIES_LDIF_PARSE_EXCEPTION.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    addEntries(entryList);
  }



  /**
   * Processes a simple bind request with the provided DN and password.  Note
   * that the bind processing will verify that the provided credentials are
   * valid, but it will not alter the server in any way.
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
  @NotNull()
  public BindResult bind(@Nullable final String bindDN,
                         @Nullable final String password)
         throws LDAPException
  {
    return bind(new SimpleBindRequest(bindDN, password));
  }



  /**
   * Processes the provided bind request.  Only simple and SASL PLAIN bind
   * requests are supported.  Note that the bind processing will verify that the
   * provided credentials are valid, but it will not alter the server in any
   * way.
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
  @NotNull()
  public BindResult bind(@NotNull final BindRequest bindRequest)
         throws LDAPException
  {
    final ArrayList<Control> requestControlList =
         new ArrayList<>(bindRequest.getControlList());
    requestControlList.add(new Control(
         InMemoryRequestHandler.OID_INTERNAL_OPERATION_REQUEST_CONTROL, false));

    final BindRequestProtocolOp bindOp;
    if (bindRequest instanceof SimpleBindRequest)
    {
      final SimpleBindRequest r = (SimpleBindRequest) bindRequest;
      bindOp = new BindRequestProtocolOp(r.getBindDN(),
           r.getPassword().getValue());
    }
    else if (bindRequest instanceof PLAINBindRequest)
    {
      final PLAINBindRequest r = (PLAINBindRequest) bindRequest;

      // Create the byte array that should comprise the credentials.
      final byte[] authZIDBytes = StaticUtils.getBytes(r.getAuthorizationID());
      final byte[] authNIDBytes = StaticUtils.getBytes(r.getAuthenticationID());
      final byte[] passwordBytes = r.getPasswordBytes();

      final byte[] credBytes = new byte[2 + authZIDBytes.length +
           authNIDBytes.length + passwordBytes.length];
      System.arraycopy(authZIDBytes, 0, credBytes, 0, authZIDBytes.length);

      int pos = authZIDBytes.length + 1;
      System.arraycopy(authNIDBytes, 0, credBytes, pos, authNIDBytes.length);

      pos += authNIDBytes.length + 1;
      System.arraycopy(passwordBytes, 0, credBytes, pos, passwordBytes.length);

      bindOp = new BindRequestProtocolOp(null, "PLAIN",
           new ASN1OctetString(credBytes));
    }
    else
    {
      throw new LDAPException(ResultCode.AUTH_METHOD_NOT_SUPPORTED,
           ERR_MEM_DS_UNSUPPORTED_BIND_TYPE.get());
    }

    final LDAPMessage responseMessage = inMemoryHandler.processBindRequest(1,
         bindOp, requestControlList);
    final BindResponseProtocolOp bindResponse =
         responseMessage.getBindResponseProtocolOp();

    final BindResult bindResult = new BindResult(new LDAPResult(
         responseMessage.getMessageID(),
         ResultCode.valueOf(bindResponse.getResultCode()),
         bindResponse.getDiagnosticMessage(), bindResponse.getMatchedDN(),
         bindResponse.getReferralURLs(), responseMessage.getControls()));

    switch (bindResponse.getResultCode())
    {
      case ResultCode.SUCCESS_INT_VALUE:
        return bindResult;
      default:
        throw new LDAPException(bindResult);
    }
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether compare operations are
   * allowed in the server.
   */
  @Override()
  @NotNull()
  public CompareResult compare(@NotNull final String dn,
                               @NotNull final String attributeName,
                               @NotNull final String assertionValue)
         throws LDAPException
  {
    return compare(new CompareRequest(dn, attributeName, assertionValue));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether compare operations are
   * allowed in the server.
   */
  @Override()
  @NotNull()
  public CompareResult compare(@NotNull final CompareRequest compareRequest)
         throws LDAPException
  {
    final ArrayList<Control> requestControlList =
         new ArrayList<>(compareRequest.getControlList());
    requestControlList.add(new Control(
         InMemoryRequestHandler.OID_INTERNAL_OPERATION_REQUEST_CONTROL, false));

    final LDAPMessage responseMessage = inMemoryHandler.processCompareRequest(1,
         new CompareRequestProtocolOp(compareRequest.getDN(),
              compareRequest.getAttributeName(),
              compareRequest.getRawAssertionValue()),
         requestControlList);

    final CompareResponseProtocolOp compareResponse =
         responseMessage.getCompareResponseProtocolOp();

    final LDAPResult compareResult = new LDAPResult(
         responseMessage.getMessageID(),
         ResultCode.valueOf(compareResponse.getResultCode()),
         compareResponse.getDiagnosticMessage(), compareResponse.getMatchedDN(),
         compareResponse.getReferralURLs(), responseMessage.getControls());

    switch (compareResponse.getResultCode())
    {
      case ResultCode.COMPARE_TRUE_INT_VALUE:
      case ResultCode.COMPARE_FALSE_INT_VALUE:
        return new CompareResult(compareResult);
      default:
        throw new LDAPException(compareResult);
    }
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether compare operations are
   * allowed in the server.
   */
  @Override()
  @NotNull()
  public CompareResult compare(
              @NotNull final ReadOnlyCompareRequest compareRequest)
         throws LDAPException
  {
    return compare(compareRequest.duplicate());
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether delete operations are
   * allowed in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult delete(@NotNull final String dn)
         throws LDAPException
  {
    return delete(new DeleteRequest(dn));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether delete operations are
   * allowed in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult delete(@NotNull final DeleteRequest deleteRequest)
         throws LDAPException
  {
    return inMemoryHandler.delete(deleteRequest);
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether delete operations are
   * allowed in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult delete(@NotNull final ReadOnlyDeleteRequest deleteRequest)
         throws LDAPException
  {
    return delete(deleteRequest.duplicate());
  }



  /**
   * Attempts to delete the specified entry and all entries below it from the
   * server.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether compare operations are
   * allowed in the server.
   *
   * @param  baseDN  The DN of the entry to remove, along with all of its
   *                 subordinates.
   *
   * @return  The number of entries removed from the server, or zero if the
   *          specified entry was not found.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         remove the entries.
   */
  public int deleteSubtree(@NotNull final String baseDN)
         throws LDAPException
  {
    return inMemoryHandler.deleteSubtree(baseDN);
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
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether extended operations are
   * allowed in the server.
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
  @NotNull()
  public ExtendedResult processExtendedOperation(
                             @NotNull final String requestOID)
         throws LDAPException
  {
    Validator.ensureNotNull(requestOID);

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
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether extended operations are
   * allowed in the server.
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
  @NotNull()
  public ExtendedResult processExtendedOperation(
                             @NotNull final String requestOID,
                             @Nullable final ASN1OctetString requestValue)
         throws LDAPException
  {
    Validator.ensureNotNull(requestOID);

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
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether extended operations are
   * allowed in the server.
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
  @NotNull()
  public ExtendedResult processExtendedOperation(
                               @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    Validator.ensureNotNull(extendedRequest);

    final ArrayList<Control> requestControlList =
         new ArrayList<>(extendedRequest.getControlList());
    requestControlList.add(new Control(
         InMemoryRequestHandler.OID_INTERNAL_OPERATION_REQUEST_CONTROL, false));


    final LDAPMessage responseMessage =
         inMemoryHandler.processExtendedRequest(1,
              new ExtendedRequestProtocolOp(extendedRequest.getOID(),
                   extendedRequest.getValue()),
              requestControlList);

    final ExtendedResponseProtocolOp extendedResponse =
         responseMessage.getExtendedResponseProtocolOp();

    final ResultCode rc = ResultCode.valueOf(extendedResponse.getResultCode());

    final String[] referralURLs;
    final List<String> referralURLList = extendedResponse.getReferralURLs();
    if ((referralURLList == null) || referralURLList.isEmpty())
    {
      referralURLs = StaticUtils.NO_STRINGS;
    }
    else
    {
      referralURLs = new String[referralURLList.size()];
      referralURLList.toArray(referralURLs);
    }

    final Control[] responseControls;
    final List<Control> controlList = responseMessage.getControls();
    if ((controlList == null) || controlList.isEmpty())
    {
      responseControls = StaticUtils.NO_CONTROLS;
    }
    else
    {
      responseControls = new Control[controlList.size()];
      controlList.toArray(responseControls);
    }

    final ExtendedResult extendedResult = new ExtendedResult(
         responseMessage.getMessageID(), rc,
         extendedResponse.getDiagnosticMessage(),
         extendedResponse.getMatchedDN(), referralURLs,
         extendedResponse.getResponseOID(),
         extendedResponse.getResponseValue(), responseControls);

    if ((extendedResult.getOID() == null) &&
        (extendedResult.getValue() == null))
    {
      switch (rc.intValue())
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

    return extendedResult;
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String dn,
                           @NotNull final Modification mod)
         throws LDAPException
  {
    return modify(new ModifyRequest(dn, mod));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String dn,
                           @NotNull final Modification... mods)
         throws LDAPException
  {
    return modify(new ModifyRequest(dn, mods));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String dn,
                           @NotNull final List<Modification> mods)
         throws LDAPException
  {
    return modify(new ModifyRequest(dn, mods));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String... ldifModificationLines)
         throws LDIFException, LDAPException
  {
    return modify(new ModifyRequest(ldifModificationLines));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final ModifyRequest modifyRequest)
         throws LDAPException
  {
    return inMemoryHandler.modify(modifyRequest);
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final ReadOnlyModifyRequest modifyRequest)
         throws LDAPException
  {
    return modify(modifyRequest.duplicate());
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify DN operations are
   * allowed in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult modifyDN(@NotNull final String dn,
                             @NotNull final String newRDN,
                             final boolean deleteOldRDN)
         throws LDAPException
  {
    return modifyDN(new ModifyDNRequest(dn, newRDN, deleteOldRDN));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify DN operations are
   * allowed in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult modifyDN(@NotNull final String dn,
                             @NotNull final String newRDN,
                             final boolean deleteOldRDN,
                             @Nullable final String newSuperiorDN)
         throws LDAPException
  {
    return modifyDN(new ModifyDNRequest(dn, newRDN, deleteOldRDN,
         newSuperiorDN));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify DN operations are
   * allowed in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult modifyDN(@NotNull final ModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return inMemoryHandler.modifyDN(modifyDNRequest);
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether modify DN operations are
   * allowed in the server.
   */
  @Override()
  @NotNull()
  public LDAPResult modifyDN(
              @NotNull final ReadOnlyModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return modifyDN(modifyDNRequest.duplicate());
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final String baseDN,
                             @NotNull final SearchScope scope,
                             @NotNull final String filter,
                             @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(baseDN, scope, parseFilter(filter),
         attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final String baseDN,
                             @NotNull final SearchScope scope,
                             @NotNull final Filter filter,
                             @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(baseDN, scope, filter, attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public SearchResult search(
               @Nullable final SearchResultListener searchResultListener,
               @NotNull final String baseDN, @NotNull final SearchScope scope,
               @NotNull final String filter,
               @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         parseFilter(filter), attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public SearchResult search(
              @Nullable final SearchResultListener searchResultListener,
              @NotNull final String baseDN, @NotNull final SearchScope scope,
              @NotNull final Filter filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         filter, attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final String baseDN,
                             @NotNull final SearchScope scope,
                             @NotNull final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly,
                             @NotNull final String filter,
                             @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(baseDN, scope, derefPolicy, sizeLimit,
         timeLimit, typesOnly, parseFilter(filter), attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final String baseDN,
                             @NotNull final SearchScope scope,
                             @NotNull final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly,
                             @NotNull final Filter filter,
                             @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(baseDN, scope, derefPolicy, sizeLimit,
         timeLimit, typesOnly, filter, attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public SearchResult search(
              @Nullable final SearchResultListener searchResultListener,
              @NotNull final String baseDN, @NotNull final SearchScope scope,
              @NotNull final DereferencePolicy derefPolicy, final int sizeLimit,
              final int timeLimit, final boolean typesOnly,
              @NotNull final String filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         derefPolicy, sizeLimit, timeLimit, typesOnly, parseFilter(filter),
         attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public SearchResult search(
              @Nullable final SearchResultListener searchResultListener,
              @NotNull final String baseDN, @NotNull final SearchScope scope,
              @NotNull final DereferencePolicy derefPolicy, final int sizeLimit,
              final int timeLimit, final boolean typesOnly,
              @NotNull final Filter filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         derefPolicy, sizeLimit, timeLimit, typesOnly, filter, attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    final ArrayList<Control> requestControlList =
         new ArrayList<>(searchRequest.getControlList());
    requestControlList.add(new Control(
         InMemoryRequestHandler.OID_INTERNAL_OPERATION_REQUEST_CONTROL, false));

    final List<SearchResultEntry> entryList =
         new ArrayList<>(10);
    final List<SearchResultReference> referenceList =
         new ArrayList<>(10);

    final LDAPMessage responseMessage = inMemoryHandler.processSearchRequest(1,
         new SearchRequestProtocolOp(searchRequest.getBaseDN(),
              searchRequest.getScope(), searchRequest.getDereferencePolicy(),
              searchRequest.getSizeLimit(), searchRequest.getTimeLimitSeconds(),
              searchRequest.typesOnly(), searchRequest.getFilter(),
              searchRequest.getAttributeList()),
         requestControlList, entryList, referenceList);


    final List<SearchResultEntry> returnEntryList;
    final List<SearchResultReference> returnReferenceList;
    final SearchResultListener searchListener =
         searchRequest.getSearchResultListener();
    if (searchListener == null)
    {
      returnEntryList = Collections.unmodifiableList(entryList);
      returnReferenceList = Collections.unmodifiableList(referenceList);
    }
    else
    {
      returnEntryList     = null;
      returnReferenceList = null;

      for (final SearchResultEntry e : entryList)
      {
        searchListener.searchEntryReturned(e);
      }

      for (final SearchResultReference r : referenceList)
      {
        searchListener.searchReferenceReturned(r);
      }
    }


    final SearchResultDoneProtocolOp searchDone =
         responseMessage.getSearchResultDoneProtocolOp();

    final ResultCode rc = ResultCode.valueOf(searchDone.getResultCode());

    final String[] referralURLs;
    final List<String> referralURLList = searchDone.getReferralURLs();
    if ((referralURLList == null) || referralURLList.isEmpty())
    {
      referralURLs = StaticUtils.NO_STRINGS;
    }
    else
    {
      referralURLs = new String[referralURLList.size()];
      referralURLList.toArray(referralURLs);
    }

    final Control[] responseControls;
    final List<Control> controlList = responseMessage.getControls();
    if ((controlList == null) || controlList.isEmpty())
    {
      responseControls = StaticUtils.NO_CONTROLS;
    }
    else
    {
      responseControls = new Control[controlList.size()];
      controlList.toArray(responseControls);
    }

    final SearchResult searchResult =new SearchResult(
         responseMessage.getMessageID(), rc, searchDone.getDiagnosticMessage(),
         searchDone.getMatchedDN(), referralURLs, returnEntryList,
         returnReferenceList, entryList.size(), referenceList.size(),
         responseControls);

    if (rc == ResultCode.SUCCESS)
    {
      return searchResult;
    }
    else
    {
      throw new LDAPSearchException(searchResult);
    }
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return search(searchRequest.duplicate());
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(@NotNull final String baseDN,
                                          @NotNull final SearchScope scope,
                                          @NotNull final String filter,
                                          @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope, parseFilter(filter),
         attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(@NotNull final String baseDN,
                                          @NotNull final SearchScope scope,
                                          @NotNull final Filter filter,
                                          @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope, filter, attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(@NotNull final String baseDN,
              @NotNull final SearchScope scope,
              @NotNull final DereferencePolicy derefPolicy,
              final int timeLimit, final boolean typesOnly,
              @NotNull final String filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope, derefPolicy, 1,
         timeLimit, typesOnly, parseFilter(filter), attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(@NotNull final String baseDN,
              @NotNull final SearchScope scope,
              @NotNull final DereferencePolicy derefPolicy,
              final int timeLimit, final boolean typesOnly,
              @NotNull final Filter filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope, derefPolicy, 1,
         timeLimit, typesOnly, filter, attributes));
  }



  /**
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(
                                @NotNull final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    final ArrayList<Control> requestControlList =
         new ArrayList<>(searchRequest.getControlList());
    requestControlList.add(new Control(
         InMemoryRequestHandler.OID_INTERNAL_OPERATION_REQUEST_CONTROL, false));

    final SearchRequest r;
    if ((searchRequest.getSizeLimit() == 1) &&
        (searchRequest.getSearchResultListener() == null))
    {
      r = searchRequest;
    }
    else
    {
      r = new SearchRequest(searchRequest.getBaseDN(), searchRequest.getScope(),
           searchRequest.getDereferencePolicy(), 1,
           searchRequest.getTimeLimitSeconds(), searchRequest.typesOnly(),
           searchRequest.getFilter(), searchRequest.getAttributes());

      r.setFollowReferrals(InternalSDKHelper.followReferralsInternal(r));
      r.setReferralConnector(InternalSDKHelper.getReferralConnectorInternal(r));
      r.setResponseTimeoutMillis(searchRequest.getResponseTimeoutMillis(null));
      r.setControls(requestControlList);
    }

    final SearchResult result;
    try
    {
      result = search(r);
    }
    catch (final LDAPSearchException lse)
    {
      Debug.debugException(lse);

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
   * {@inheritDoc}
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections, and regardless of whether search operations are allowed
   * in the server.
   */
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(
              @NotNull final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return searchForEntry(searchRequest.duplicate());
  }



  /**
   * Retrieves the configured list of password attributes.
   *
   * @return  The configured list of password attributes.
   */
  @NotNull()
  public List<String> getPasswordAttributes()
  {
    return inMemoryHandler.getPasswordAttributes();
  }



  /**
   * Retrieves the primary password encoder that has been configured for the
   * server.
   *
   * @return  The primary password encoder that has been configured for the
   *          server.
   */
  @Nullable()
  public InMemoryPasswordEncoder getPrimaryPasswordEncoder()
  {
    return inMemoryHandler.getPrimaryPasswordEncoder();
  }



  /**
   * Retrieves a list of all password encoders configured for the server.
   *
   * @return  A list of all password encoders configured for the server.
   */
  @NotNull()
  public List<InMemoryPasswordEncoder> getAllPasswordEncoders()
  {
    return inMemoryHandler.getAllPasswordEncoders();
  }



  /**
   * Retrieves a list of the passwords contained in the provided entry.
   *
   * @param  entry                 The entry from which to obtain the list of
   *                               passwords.  It must not be {@code null}.
   * @param  clearPasswordToMatch  An optional clear-text password that should
   *                               match the values that are returned.  If this
   *                               is {@code null}, then all passwords contained
   *                               in the provided entry will be returned.  If
   *                               this is non-{@code null}, then only passwords
   *                               matching the clear-text password will be
   *                               returned.
   *
   * @return  A list of the passwords contained in the provided entry,
   *          optionally restricted to those matching the provided clear-text
   *          password, or an empty list if the entry does not contain any
   *          passwords.
   */
  @NotNull()
  public List<InMemoryDirectoryServerPassword> getPasswordsInEntry(
              @NotNull final Entry entry,
              @Nullable final ASN1OctetString clearPasswordToMatch)
  {
    return inMemoryHandler.getPasswordsInEntry(entry, clearPasswordToMatch);
  }



  /**
   * Parses the provided string as a search filter.
   *
   * @param  s  The string to be parsed.
   *
   * @return  The parsed filter.
   *
   * @throws  LDAPSearchException  If the provided string could not be parsed as
   *                               a valid search filter.
   */
  @NotNull()
  private static Filter parseFilter(@NotNull final String s)
          throws LDAPSearchException
  {
    try
    {
      return Filter.create(s);
    }
    catch (final LDAPException le)
    {
      throw new LDAPSearchException(le);
    }
  }



  /**
   * Indicates whether the specified entry exists in the server.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn  The DN of the entry for which to make the determination.
   *
   * @return  {@code true} if the entry exists, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public boolean entryExists(@NotNull final String dn)
         throws LDAPException
  {
    return inMemoryHandler.entryExists(dn);
  }



  /**
   * Indicates whether the specified entry exists in the server and matches the
   * given filter.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn      The DN of the entry for which to make the determination.
   * @param  filter  The filter the entry is expected to match.
   *
   * @return  {@code true} if the entry exists and matches the specified filter,
   *          or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public boolean entryExists(@NotNull final String dn,
                             @NotNull final String filter)
         throws LDAPException
  {
    return inMemoryHandler.entryExists(dn, filter);
  }



  /**
   * Indicates whether the specified entry exists in the server.  This will
   * return {@code true} only if the target entry exists and contains all values
   * for all attributes of the provided entry.  The entry will be allowed to
   * have attribute values not included in the provided entry.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  entry  The entry to compare against the directory server.
   *
   * @return  {@code true} if the entry exists in the server and is a superset
   *          of the provided entry, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public boolean entryExists(@NotNull final Entry entry)
         throws LDAPException
  {
    return inMemoryHandler.entryExists(entry);
  }



  /**
   * Ensures that an entry with the provided DN exists in the directory.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn  The DN of the entry for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist.
   */
  public void assertEntryExists(@NotNull final String dn)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntryExists(dn);
  }



  /**
   * Ensures that an entry with the provided DN exists in the directory.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn      The DN of the entry for which to make the determination.
   * @param  filter  A filter that the target entry must match.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          match the provided filter.
   */
  public void assertEntryExists(@NotNull final String dn,
                                @NotNull final String filter)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntryExists(dn, filter);
  }



  /**
   * Ensures that an entry exists in the directory with the same DN and all
   * attribute values contained in the provided entry.  The server entry may
   * contain additional attributes and/or attribute values not included in the
   * provided entry.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  entry  The entry expected to be present in the directory server.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          match the provided filter.
   */
  public void assertEntryExists(@NotNull final Entry entry)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntryExists(entry);
  }



  /**
   * Retrieves a list containing the DNs of the entries which are missing from
   * the directory server.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dns  The DNs of the entries to try to find in the server.
   *
   * @return  A list containing all of the provided DNs that were not found in
   *          the server, or an empty list if all entries were found.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @NotNull()
  public List<String> getMissingEntryDNs(@NotNull final String... dns)
         throws LDAPException
  {
    return inMemoryHandler.getMissingEntryDNs(StaticUtils.toList(dns));
  }



  /**
   * Retrieves a list containing the DNs of the entries which are missing from
   * the directory server.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dns  The DNs of the entries to try to find in the server.
   *
   * @return  A list containing all of the provided DNs that were not found in
   *          the server, or an empty list if all entries were found.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @NotNull()
  public List<String> getMissingEntryDNs(@NotNull final Collection<String> dns)
         throws LDAPException
  {
    return inMemoryHandler.getMissingEntryDNs(dns);
  }



  /**
   * Ensures that all of the entries with the provided DNs exist in the
   * directory.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dns  The DNs of the entries for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If any of the target entries does not exist.
   */
  public void assertEntriesExist(@NotNull final String... dns)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntriesExist(StaticUtils.toList(dns));
  }



  /**
   * Ensures that all of the entries with the provided DNs exist in the
   * directory.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dns  The DNs of the entries for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If any of the target entries does not exist.
   */
  public void assertEntriesExist(@NotNull final Collection<String> dns)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntriesExist(dns);
  }



  /**
   * Retrieves a list containing all of the named attributes which do not exist
   * in the target entry.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes expected to be present
   *                         in the target entry.
   *
   * @return  A list containing the names of the attributes which were not
   *          present in the target entry, an empty list if all specified
   *          attributes were found in the entry, or {@code null} if the target
   *          entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  public List<String> getMissingAttributeNames(@NotNull final String dn,
                           @NotNull final String... attributeNames)
         throws LDAPException
  {
    return inMemoryHandler.getMissingAttributeNames(dn,
         StaticUtils.toList(attributeNames));
  }



  /**
   * Retrieves a list containing all of the named attributes which do not exist
   * in the target entry.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes expected to be present
   *                         in the target entry.
   *
   * @return  A list containing the names of the attributes which were not
   *          present in the target entry, an empty list if all specified
   *          attributes were found in the entry, or {@code null} if the target
   *          entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  public List<String> getMissingAttributeNames(@NotNull final String dn,
                           @NotNull final Collection<String> attributeNames)
         throws LDAPException
  {
    return inMemoryHandler.getMissingAttributeNames(dn, attributeNames);
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified attributes.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes that are expected to be
   *                         present in the provided entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          contain all of the specified attributes.
   */
  public void assertAttributeExists(@NotNull final String dn,
                                    @NotNull final String... attributeNames)
        throws LDAPException, AssertionError
  {
    inMemoryHandler.assertAttributeExists(dn,
         StaticUtils.toList(attributeNames));
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified attributes.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes that are expected to be
   *                         present in the provided entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          contain all of the specified attributes.
   */
  public void assertAttributeExists(@NotNull final String dn,
                   @NotNull final Collection<String> attributeNames)
        throws LDAPException, AssertionError
  {
    inMemoryHandler.assertAttributeExists(dn, attributeNames);
  }



  /**
   * Retrieves a list of all provided attribute values which are missing from
   * the specified entry.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The attribute expected to be present in the target
   *                          entry with the given values.
   * @param  attributeValues  The values expected to be present in the target
   *                          entry.
   *
   * @return  A list containing all of the provided values which were not found
   *          in the entry, an empty list if all provided attribute values were
   *          found, or {@code null} if the target entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  public List<String> getMissingAttributeValues(@NotNull final String dn,
                           @NotNull final String attributeName,
                           @NotNull final String... attributeValues)
         throws LDAPException
  {
    return inMemoryHandler.getMissingAttributeValues(dn, attributeName,
         StaticUtils.toList(attributeValues));
  }



  /**
   * Retrieves a list of all provided attribute values which are missing from
   * the specified entry.  The target attribute may or may not contain
   * additional values.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The attribute expected to be present in the target
   *                          entry with the given values.
   * @param  attributeValues  The values expected to be present in the target
   *                          entry.
   *
   * @return  A list containing all of the provided values which were not found
   *          in the entry, an empty list if all provided attribute values were
   *          found, or {@code null} if the target entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  public List<String> getMissingAttributeValues(@NotNull final String dn,
                           @NotNull final String attributeName,
                           @NotNull final Collection<String> attributeValues)
       throws LDAPException
  {
    return inMemoryHandler.getMissingAttributeValues(dn, attributeName,
         attributeValues);
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified values for the given attribute.  The attribute may or may not
   * contain additional values.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The set of values which must exist for the given
   *                          attribute.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist, does not
   *                          contain the specified attribute, or that attribute
   *                          does not have all of the specified values.
   */
  public void assertValueExists(@NotNull final String dn,
                                @NotNull final String attributeName,
                                @NotNull final String... attributeValues)
        throws LDAPException, AssertionError
  {
    inMemoryHandler.assertValueExists(dn, attributeName,
         StaticUtils.toList(attributeValues));
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified values for the given attribute.  The attribute may or may not
   * contain additional values.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The set of values which must exist for the given
   *                          attribute.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist, does not
   *                          contain the specified attribute, or that attribute
   *                          does not have all of the specified values.
   */
  public void assertValueExists(@NotNull final String dn,
                   @NotNull final String attributeName,
                   @NotNull final Collection<String> attributeValues)
        throws LDAPException, AssertionError
  {
    inMemoryHandler.assertValueExists(dn, attributeName, attributeValues);
  }



  /**
   * Ensures that the specified entry does not exist in the directory.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn  The DN of the entry expected to be missing.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is found in the server.
   */
  public void assertEntryMissing(@NotNull final String dn)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntryMissing(dn);
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attributes.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn              The DN of the entry expected to be present.
   * @param  attributeNames  The names of the attributes expected to be missing
   *                         from the entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attributes.
   */
  public void assertAttributeMissing(@NotNull final String dn,
                                     @NotNull final String... attributeNames)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertAttributeMissing(dn,
         StaticUtils.toList(attributeNames));
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attributes.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn              The DN of the entry expected to be present.
   * @param  attributeNames  The names of the attributes expected to be missing
   *                         from the entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attributes.
   */
  public void assertAttributeMissing(@NotNull final String dn,
                   @NotNull final Collection<String> attributeNames)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertAttributeMissing(dn, attributeNames);
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attribute values.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn               The DN of the entry expected to be present.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The values expected to be missing from the target
   *                          entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attribute values.
   */
  public void assertValueMissing(@NotNull final String dn,
                                 @NotNull final String attributeName,
                                 @NotNull final String... attributeValues)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertValueMissing(dn, attributeName,
         StaticUtils.toList(attributeValues));
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attribute values.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn               The DN of the entry expected to be present.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The values expected to be missing from the target
   *                          entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attribute values.
   */
  public void assertValueMissing(@NotNull final String dn,
                   @NotNull final String attributeName,
                   @NotNull final Collection<String> attributeValues)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertValueMissing(dn, attributeName, attributeValues);
  }
}
