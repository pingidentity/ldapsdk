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



import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import javax.net.SocketFactory;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides a utility that may be used to create a simple LDAP server
 * instance that will hold all of its information in memory.  This is primarily
 * intended for testing purposes, and the server will not be fully standards
 * compliant.
 * <BR><BR>
 * Some notes about the capabilities of this server:
 * <UL>
 *   <LI>It provides reasonably complete support for add, compare, delete,
 *       modify, modify DN (including new superior and subtree move/rename),
 *       search, and unbind operations.</LI>
 *   <LI>It will accept abandon requests, but will not do anything with
 *       them.</LI>
 *   <LI>It provides support for simple bind operations.  It does not currently
 *       support any form of SASL authentication.</LI>
 *   <LI>It does not currently support any extended operations.</LI>
 *   <LI>It does not currently support any request or response controls.</LI>
 *   <LI>It does not currently support smart referrals.</LI>
 *   <LI>It supports the use of schema (if provided), but it does not currently
 *       allow updating the schema on the fly.</LI>
 * </UL>
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process that can be used to create,
 * start, and use an in-memory directory server instance:
 * <PRE>
 * // Create a base configuration for the server.
 * InMemoryDirectoryServerConfig config =
 *      new InMemoryDirectoryServerConfig("dc=example,dc=com");
 * config.setSchema(Schema.getDefaultStandardSchema());
 * config.addAdditionalBindCredentials("cn=Directory Manager",
 *      "password");
 *
 * // Create and start the server instance and populate it with an
 * // initial set of data from the file "/tmp;test.ldif".
 * InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);
 * server.initializeFromLDIF(true, "/tmp/test.ldif");
 *
 * // Start the server so it will accept client connections.
 * int listenPort = server.startListening();
 *
 * // Get a connection to the server.
 * LDAPConnection conn = server.getConnection();
 *
 * // Perform various operations in the server....
 *
 * // Close the connection.
 * conn.close();
 *
 * // Shut down the server so that it will no longer accept client
 * // connections, and close all existing connections.
 * server.shutDown(true);
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class InMemoryDirectoryServer
{
  // The in-memory request handler that will be used for the server.
  private final InMemoryRequestHandler inMemoryHandler;

  // The LDAP listener that will be used to interact with clients.
  private final LDAPListener listener;

  // The socket factory that should be used when trying to create client
  // connections.
  private final SocketFactory clientSocketFactory;



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
  public InMemoryDirectoryServer(final String... baseDNs)
         throws LDAPException
  {
    this(new InMemoryDirectoryServerConfig(baseDNs));
  }



  /**
   * Creates a new instance of an in-memory directory server with the provided
   * configuration.
   *
   * @param  config  The configuration to use for the server.  It must not be
   *                 {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while trying to initialize the
   *                         directory server with the provided configuration.
   */
  public InMemoryDirectoryServer(final InMemoryDirectoryServerConfig config)
         throws LDAPException
  {
    Validator.ensureNotNull(config);

    inMemoryHandler = new InMemoryRequestHandler(config);

    LDAPListenerRequestHandler requestHandler = inMemoryHandler;

    if (config.getAccessLogHandler() != null)
    {
      requestHandler = new AccessLogRequestHandler(config.getAccessLogHandler(),
           requestHandler);
    }

    if (config.getLDAPDebugLogHandler() != null)
    {
      requestHandler = new LDAPDebuggerRequestHandler(
           config.getLDAPDebugLogHandler(), requestHandler);
    }

    final LDAPListenerConfig listenerConfig =
         new LDAPListenerConfig(config.getListenPort(), requestHandler);
    listenerConfig.setExceptionHandler(config.getListenerExceptionHandler());
    listenerConfig.setListenAddress(config.getListenAddress());
    listenerConfig.setServerSocketFactory(config.getServerSocketFactory());

    listener = new LDAPListener(listenerConfig);

    clientSocketFactory = config.getClientSocketFactory();
  }



  /**
   * Causes the server to start listening for client connections.  This method
   * will return as soon as the listener has started.  This method may only be
   * called once on a single object instance, so one a server has been shut
   * down it cannot be re-started, and it will be necessary to create a new
   * instance and start that.
   *
   * @return  The port on which the server is listening for client connections.
   *
   * @throws  IOException  If a problem occurs while attempting to create the
   *                       listen socket.
   */
  public int startListening()
         throws IOException
  {
    listener.startListening();
    return listener.getListenPort();
  }



  /**
   * Indicates that the server should stop accepting new connections.  It may
   * optionally close all connections that have already been established.  Note
   * that once a server instance has been shut down, it cannot be re-started,
   * and a new instance will be required.
   *
   * @param  closeExistingConnections  Indicates whether to close all existing
   *                                   connections, or merely to stop accepting
   *                                   new connections.
   */
  public void shutDown(final boolean closeExistingConnections)
  {
    listener.shutDown(closeExistingConnections);
  }



  /**
   * Retrieves the in-memory request handler that is used to perform the real
   * server processing.
   *
   * @return  The in-memory request handler that is used to perform the real
   *          server processing.
   */
  InMemoryRequestHandler getInMemoryRequestHandler()
  {
    return inMemoryHandler;
  }



  /**
   * Creates a point-in-time snapshot of the information contained in this
   * in-memory directory server instance.  It may be restored using the
   * {@link #restoreSnapshot} method.
   *
   * @return  The snapshot created based on the current content of this
   *          in-memory directory server instance.
   */
  public InMemoryDirectoryServerSnapshot createSnapshot()
  {
    return inMemoryHandler.createSnapshot();
  }



  /**
   * Restores the this in-memory directory server instance to match the content
   * it held at the time the snapshot was created.
   *
   * @param  snapshot  The snapshot to be restored.  It must not be
   *                   {@code null}.
   */
  public void restoreSnapshot(final InMemoryDirectoryServerSnapshot snapshot)
  {
    inMemoryHandler.restoreSnapshot(snapshot);
  }



  /**
   * Retrieves the address on which the server is currently listening for client
   * connections.
   *
   * @return  The address on which the server is currently listening for client
   *          connections, or {@code null} if it is not currently listening.
   */
  public InetAddress getListenAddress()
  {
    return listener.getListenAddress();
  }



  /**
   * Retrieves the port on which the server is currently listening for client
   * connections.
   *
   * @return  The port on which the server is currently listening for client
   *          connections, or -1 if it is not currently listening.
   */
  public int getListenPort()
  {
    return listener.getListenPort();
  }



  /**
   * Retrieves the list of base DNs configured for use by the server.
   *
   * @return  The list of base DNs configured for use by the server.
   */
  public List<DN> getBaseDNs()
  {
    return inMemoryHandler.getBaseDNs();
  }



  /**
   * Retrieves the schema used by the server, if available.
   *
   * @return  The schema used by the server, or {@code null} if none is
   *          available.
   */
  public Schema getSchema()
  {
    return inMemoryHandler.getSchema();
  }



  /**
   * Attempts to establish a client connection to the server.
   *
   * @return  The client connection that has been established.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         create the connection.
   */
  public LDAPConnection getConnection()
         throws LDAPException
  {
    return getConnection(null);
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
  public LDAPConnection getConnection(final LDAPConnectionOptions options)
         throws LDAPException
  {
    final int listenPort = listener.getListenPort();
    if (listenPort < 0)
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_MEM_DS_GET_CONNECTION_NOT_LISTENING.get());
    }

    String hostAddress;
    final InetAddress listenAddress = listener.getListenAddress();
    if (listenAddress.isAnyLocalAddress())
    {
      try
      {
        hostAddress = InetAddress.getLocalHost().getHostAddress();
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
         listenPort);
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
  public LDAPConnectionPool getConnectionPool(final int maxConnections)
         throws LDAPException
  {
    return getConnectionPool(null, 1, maxConnections);
  }



  /**
   * Attempts to establish a connection pool to the server with the provided
   * settings.
   *
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
  public LDAPConnectionPool getConnectionPool(
                                 final LDAPConnectionOptions options,
                                 final int initialConnections,
                                 final int maxConnections)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection(options);
    return new LDAPConnectionPool(conn, initialConnections, maxConnections);
  }



  /**
   * Retrieves the number of entries currently held in the server.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @return  The number of entries currently held in the server.
   */
  public int countEntries()
  {
    return inMemoryHandler.countEntries();
  }



  /**
   * Removes all entries held in the server.
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
  public int initializeFromLDIF(final boolean clear, final String path)
         throws LDAPException
  {
    final LDIFReader reader;
    try
    {
      reader = new LDIFReader(path);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_MEM_DS_INIT_FROM_LDIF_CANNOT_CREATE_READER.get(path,
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    return initializeFromLDIF(clear, reader);
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
  public int initializeFromLDIF(final boolean clear, final LDIFReader reader)
         throws LDAPException
  {
    return inMemoryHandler.initializeFromLDIF(clear, reader);
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
  public int writeToLDIF(final String path, final boolean excludeGeneratedAttrs,
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

    return writeToLDIF(ldifWriter, excludeGeneratedAttrs, excludeChangeLog,
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
  public int writeToLDIF(final LDIFWriter ldifWriter,
                         final boolean excludeGeneratedAttrs,
                         final boolean excludeChangeLog,
                         final boolean closeWriter)
         throws LDAPException
  {
    return inMemoryHandler.writeToLDIF(ldifWriter, excludeGeneratedAttrs,
         excludeChangeLog, closeWriter);
  }



  /**
   * Attempts to add the provided entry to the server.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  ldifEntry  The lines comprising the LDIF representation of the
   *                    entry to be added.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to add
   *                         the provided entry.
   */
  public void addEntry(final String... ldifEntry)
         throws LDAPException
  {
    try
    {
      addEntry(new Entry(ldifEntry));
    }
    catch (final LDIFException le)
    {
      Debug.debugException(le);
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_ADD_ENTRY_LDIF_PARSE_EXCEPTION.get(le.getMessage()), le);
    }
  }



  /**
   * Attempts to add the provided entry to the server.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  entry  The entry to be written.  It must not be {@code null}.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to add
   *                         the provided entry.
   */
  public void addEntry(final Entry entry)
         throws LDAPException
  {
    inMemoryHandler.addEntry(entry, false);
  }



  /**
   * Attempts to add all of the provided entries to the server.  If a problem is
   * encountered while attempting to add any of the provided entries, then the
   * server will remain populated with the data it held before this method was
   * called.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  entries  The entries to be added to the server.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to add
   *                         any of the provided entries.
   */
  public void addEntries(final Entry... entries)
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
   * client connections.
   *
   * @param  entries  The entries to be added to the server.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to add
   *                         any of the provided entries.
   */
  public void addEntries(final List<? extends Entry> entries)
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
   * client connections.
   *
   * @param  ldifEntryLines  The lines comprising the LDIF representation of the
   *                         entries to be added.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to add
   *                         any of the provided entries.
   */
  public void addEntries(final String... ldifEntryLines)
         throws LDAPException
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    for (final String line : ldifEntryLines)
    {
      buffer.append(line);
      buffer.append(StaticUtils.EOL_BYTES);
    }

    final ArrayList<Entry> entryList = new ArrayList<Entry>(10);
    final LDIFReader reader = new LDIFReader(buffer.asInputStream());
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
   * Attempts to delete the specified entry from the server.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn  The DN of the entry to remove from the server.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         remove the specified entry.
   */
  public void deleteEntry(final String dn)
         throws LDAPException
  {
    inMemoryHandler.deleteEntry(dn);
  }



  /**
   * Attempts to delete the specified entry and all entries below it from the
   * server.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
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
  public int deleteSubtree(final String baseDN)
         throws LDAPException
  {
    return inMemoryHandler.deleteSubtree(baseDN);
  }



  /**
   * Attempts to apply the provided set of modifications to the specified
   * entry.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn    The DN of the entry to modify.
   * @param  mods  The modifications to apply to the entry.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         modify the entry.
   */
  public void modifyEntry(final String dn, final Modification... mods)
         throws LDAPException
  {
    modifyEntry(dn, Arrays.asList(mods));
  }



  /**
   * Attempts to apply the provided set of modifications to the specified
   * entry.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn    The DN of the entry to modify.
   * @param  mods  The modifications to apply to the entry.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         modify the entry.
   */
  public void modifyEntry(final String dn, final List<Modification> mods)
         throws LDAPException
  {
    inMemoryHandler.modifyEntry(dn, mods);
  }



  /**
   * Attempts to apply the provided modification in the server.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  ldifModification  The lines that comprise the LDIF representation
   *                           of the modification to be applied.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         process the modification.
   */
  public void modifyEntry(final String... ldifModification)
         throws LDAPException
  {
    final ModifyRequest modifyRequest;
    try
    {
      modifyRequest = new ModifyRequest(ldifModification);
    }
    catch (final LDIFException le)
    {
      Debug.debugException(le);
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MEM_DS_MODIFY_ENTRY_LDIF_PARSE_EXCEPTION.get( le.getMessage()),
           le);
    }

    modifyEntry(modifyRequest.getDN(), modifyRequest.getModifications());
  }



  /**
   * Retrieves a read-only copy of the specified entry from the server.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  dn  The DN of the entry to retrieve.
   *
   * @return  The a read-only copy of the requested entry, or {@code null} if it
   *          does not exist in the server.
   *
   * @throws  LDAPException  If the provided DN is malformed.
   */
  public ReadOnlyEntry getEntry(final String dn)
         throws LDAPException
  {
    return inMemoryHandler.getEntry(dn);
  }



  /**
   * Retrieves a list of all entries in the server which match the given
   * search criteria.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  baseDN  The base DN to use for the search.  It must not be
   *                 {@code null}.
   * @param  scope   The scope to use for the search.  It must not be
   *                 {@code null}.
   * @param  filter  The filter to use for the search.  It must not be
   *                 {@code null}.
   *
   * @return  A list of the entries that matched the provided search criteria.
   *
   * @throws  LDAPException  If a problem is encountered while performing the
   *                         search.
   */
  public List<ReadOnlyEntry> search(final String baseDN,
                                    final SearchScope scope,
                                    final String filter)
         throws LDAPException
  {
    return search(baseDN, scope, Filter.create(filter));
  }



  /**
   * Retrieves a list of all entries in the server which match the given
   * search criteria.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  baseDN  The base DN to use for the search.  It must not be
   *                 {@code null}.
   * @param  scope   The scope to use for the search.  It must not be
   *                 {@code null}.
   * @param  filter  The filter to use for the search.  It must not be
   *                 {@code null}.
   *
   * @return  A list of the entries that matched the provided search criteria.
   *
   * @throws  LDAPException  If a problem is encountered while performing the
   *                         search.
   */
  public List<ReadOnlyEntry> search(final String baseDN,
                                    final SearchScope scope,
                                    final Filter filter)
         throws LDAPException
  {
    return inMemoryHandler.search(baseDN, scope, filter);
  }



  /**
   * Indicates whether the specified entry exists in the server.
   *
   * @param  dn  The DN of the entry for which to make the determination.
   *
   * @return  {@code true} if the entry exists, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public boolean entryExists(final String dn)
         throws LDAPException
  {
    return inMemoryHandler.entryExists(dn);
  }



  /**
   * Indicates whether the specified entry exists in the server and matches the
   * given filter.
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
  public boolean entryExists(final String dn, final String filter)
         throws LDAPException
  {
    return inMemoryHandler.entryExists(dn, filter);
  }



  /**
   * Indicates whether the specified entry exists in the server.  This will
   * return {@code true} only if the target entry exists and contains all values
   * for all attributes of the provided entry.  The entry will be allowed to
   * have attribute values not included in the provided entry.
   *
   * @param  entry  The entry to compare against the directory server.
   *
   * @return  {@code true} if the entry exists in the server and is a superset
   *          of the provided entry, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public boolean entryExists(final Entry entry)
         throws LDAPException
  {
    return inMemoryHandler.entryExists(entry);
  }



  /**
   * Ensures that an entry with the provided DN exists in the directory.
   *
   * @param  dn  The DN of the entry for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist.
   */
  public void assertEntryExists(final String dn)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntryExists(dn);
  }



  /**
   * Ensures that an entry with the provided DN exists in the directory.
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
  public void assertEntryExists(final String dn, final String filter)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntryExists(dn, filter);
  }



  /**
   * Ensures that an entry exists in the directory with the same DN and all
   * attribute values contained in the provided entry.  The server entry may
   * contain additional attributes and/or attribute values not included in the
   * provided entry.
   *
   * @param  entry  The entry expected to be present in the directory server.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          match the provided filter.
   */
  public void assertEntryExists(final Entry entry)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntryExists(entry);
  }



  /**
   * Retrieves a list containing the DNs of the entries which are missing from
   * the directory server.
   *
   * @param  dns  The DNs of the entries to try to find in the server.
   *
   * @return  A list containing all of the provided DNs that were not found in
   *          the server, or an empty list if all entries were found.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public List<String> getMissingEntryDNs(final String... dns)
         throws LDAPException
  {
    return inMemoryHandler.getMissingEntryDNs(StaticUtils.toList(dns));
  }



  /**
   * Retrieves a list containing the DNs of the entries which are missing from
   * the directory server.
   *
   * @param  dns  The DNs of the entries to try to find in the server.
   *
   * @return  A list containing all of the provided DNs that were not found in
   *          the server, or an empty list if all entries were found.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public List<String> getMissingEntryDNs(final Collection<String> dns)
         throws LDAPException
  {
    return inMemoryHandler.getMissingEntryDNs(dns);
  }



  /**
   * Ensures that all of the entries with the provided DNs exist in the
   * directory.
   *
   * @param  dns  The DNs of the entries for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If any of the target entries does not exist.
   */
  public void assertEntriesExist(final String... dns)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntriesExist(StaticUtils.toList(dns));
  }



  /**
   * Ensures that all of the entries with the provided DNs exist in the
   * directory.
   *
   * @param  dns  The DNs of the entries for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If any of the target entries does not exist.
   */
  public void assertEntriesExist(final Collection<String> dns)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntriesExist(dns);
  }



  /**
   * Retrieves a list containing all of the named attributes which do not exist
   * in the target entry.
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
  public List<String> getMissingAttributeNames(final String dn,
                                               final String... attributeNames)
         throws LDAPException
  {
    return inMemoryHandler.getMissingAttributeNames(dn,
         StaticUtils.toList(attributeNames));
  }



  /**
   * Retrieves a list containing all of the named attributes which do not exist
   * in the target entry.
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
  public List<String> getMissingAttributeNames(final String dn,
                           final Collection<String> attributeNames)
         throws LDAPException
  {
    return inMemoryHandler.getMissingAttributeNames(dn, attributeNames);
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified attributes.
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
  public void assertAttributeExists(final String dn,
                                    final String... attributeNames)
        throws LDAPException, AssertionError
  {
    inMemoryHandler.assertAttributeExists(dn,
         StaticUtils.toList(attributeNames));
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified attributes.
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
  public void assertAttributeExists(final String dn,
                                    final Collection<String> attributeNames)
        throws LDAPException, AssertionError
  {
    inMemoryHandler.assertAttributeExists(dn, attributeNames);
  }



  /**
   * Retrieves a list of all provided attribute values which are missing from
   * the specified entry.
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
  public List<String> getMissingAttributeValues(final String dn,
                                                final String attributeName,
                                                final String... attributeValues)
         throws LDAPException
  {
    return inMemoryHandler.getMissingAttributeValues(dn, attributeName,
         StaticUtils.toList(attributeValues));
  }



  /**
   * Retrieves a list of all provided attribute values which are missing from
   * the specified entry.  The target attribute may or may not contain
   * additional values.
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
  public List<String> getMissingAttributeValues(final String dn,
                           final String attributeName,
                           final Collection<String> attributeValues)
       throws LDAPException
  {
    return inMemoryHandler.getMissingAttributeValues(dn, attributeName,
         attributeValues);
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified values for the given attribute.  The attribute may or may not
   * contain additional values.
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
  public void assertValueExists(final String dn, final String attributeName,
                                final String... attributeValues)
        throws LDAPException, AssertionError
  {
    inMemoryHandler.assertValueExists(dn, attributeName,
         StaticUtils.toList(attributeValues));
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified values for the given attribute.  The attribute may or may not
   * contain additional values.
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
  public void assertValueExists(final String dn, final String attributeName,
                                final Collection<String> attributeValues)
        throws LDAPException, AssertionError
  {
    inMemoryHandler.assertValueExists(dn, attributeName, attributeValues);
  }



  /**
   * Ensures that the specified entry does not exist in the directory.
   *
   * @param  dn  The DN of the entry expected to be missing.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is found in the server.
   */
  public void assertEntryMissing(final String dn)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertEntryMissing(dn);
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attributes.
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
  public void assertAttributeMissing(final String dn,
                                     final String... attributeNames)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertAttributeMissing(dn,
         StaticUtils.toList(attributeNames));
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attributes.
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
  public void assertAttributeMissing(final String dn,
                                     final Collection<String> attributeNames)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertAttributeMissing(dn, attributeNames);
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attribute values.
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
  public void assertValueMissing(final String dn, final String attributeName,
                                 final String... attributeValues)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertValueMissing(dn, attributeName,
         StaticUtils.toList(attributeValues));
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attribute values.
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
  public void assertValueMissing(final String dn, final String attributeName,
                                 final Collection<String> attributeValues)
         throws LDAPException, AssertionError
  {
    inMemoryHandler.assertValueMissing(dn, attributeName, attributeValues);
  }
}
