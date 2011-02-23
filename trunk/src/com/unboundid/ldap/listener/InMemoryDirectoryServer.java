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

    inMemoryHandler = new InMemoryRequestHandler(config.getSchema(),
         config.getBaseDNs());
    inMemoryHandler.setAdditionalBindCredentials(
         config.getAdditionalBindCredentials());

    final LDAPListenerRequestHandler requestHandler;
    if (config.getAccessLogHandler() == null)
    {
      requestHandler = inMemoryHandler;
    }
    else
    {
      requestHandler = new AccessLogRequestHandler(config.getAccessLogHandler(),
           inMemoryHandler);
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
   * @param  path  The path of the file to which the LDIF entries should be
   *               written.
   *
   * @return  The number of entries written to LDIF.
   *
   * @throws  LDAPException  If a problem occurs while writing entries to LDIF.
   */
  public int writeToLDIF(final String path)
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

    return writeToLDIF(ldifWriter, true);
  }



  /**
   * Writes the current contents of the server in LDIF form using the provided
   * LDIF writer.
   * <BR><BR>
   * This method may be used regardless of whether the server is listening for
   * client connections.
   *
   * @param  writer       The LDIF writer to use to write entries.
   * @param  closeWriter  Indicates whether the provided LDIF writer should be
   *                      closed after all server entries have been written to
   *                      it.
   *
   * @return  The number of entries written to LDIF.
   *
   * @throws  LDAPException  If a problem occurs while writing entries to LDIF.
   */
  public int writeToLDIF(final LDIFWriter writer, final boolean closeWriter)
         throws LDAPException
  {
    return inMemoryHandler.writeToLDIF(writer, closeWriter);
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
}
