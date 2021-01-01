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
package com.unboundid.ldap.sdk;



import java.io.Closeable;
import java.util.Collection;
import java.util.List;

import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides an implementation of a special type of LDAP connection
 * pool which maintains two separate sets of connections:  one for read
 * operations and the other for write operations.  The "write" connections will
 * be used for add, delete, modify, and modify DN operations, and the "read"
 * connections will be used for all other processing including bind, compare,
 * and search operations, as well as methods like {@link #getEntry},
 * {@link #getRootDSE}, and {@link #getSchema}.  If the target directory
 * environment does not require separate servers for read and write operations,
 * then it is recommended that the simpler {@link LDAPConnectionPool} class be
 * used instead.
 * <BR><BR>
 * This class is very similar to the {@code LDAPConnectionPool} class with the
 * exception that it is possible to explicitly check out and release connections
 * from either the read or write pools, and there is no convenience method for
 * processing multiple requests over the same connection.  See the documentation
 * for the {@link LDAPConnectionPool} class for additional documentation and
 * for examples demonstrating the use of both connection pool implementations.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPReadWriteConnectionPool
       implements LDAPInterface, Closeable
{
  // The connection pool used for read operations.
  @NotNull private final LDAPConnectionPool readPool;

  // The connection pool used for write operations.
  @NotNull private final LDAPConnectionPool writePool;



  /**
   * Creates a new LDAP read-write connection pool with the provided
   * connections.
   *
   * @param  readConnection           The connection to use to provide the
   *                                  template for other connections to be
   *                                  created for performing read operations.
   *                                  This connection will be included in the
   *                                  pool.  It must not be {@code null}, and it
   *                                  must be established to the target server.
   *                                  It does not necessarily need to be
   *                                  authenticated if all read connections are
   *                                  to be unauthenticated.
   * @param  initialReadConnections   The number of connections to initially
   *                                  establish in the pool that is created for
   *                                  read operations.  It must be greater than
   *                                  or equal to one.
   * @param  maxReadConnections       The maximum number of connections that
   *                                  should be maintained in the read pool.
   *                                  It must be greater than or equal to the
   *                                  initial number of write connections.
   * @param  writeConnection          The connection to use to provide the
   *                                  template for other connections to be
   *                                  created for performing write operations.
   *                                  This connection will be included in the
   *                                  pool.  It must not be {@code null}, and it
   *                                  must be established to the target server.
   *                                  It does not necessarily need to be
   *                                  authenticated if all write connections are
   *                                  to be unauthenticated.
   * @param  initialWriteConnections  The number of connections to initially
   *                                  establish in the pool that is created for
   *                                  write operations.  It must be greater than
   *                                  or equal to one.
   * @param  maxWriteConnections      The maximum number of connections that
   *                                  should be maintained in the write pool.
   *                                  It must be greater than or equal to the
   *                                  initial number of write connections.
   *
   * @throws  LDAPException  If either of the provided connections cannot be
   *                         used to initialize the pool, or if a problem occurs
   *                         while attempting to establish any of the
   *                         connections.  If this is thrown, then all
   *                         connections associated with this pool (including
   *                         the read and write connections provided as
   *                         arguments) will be closed.
   */
  public LDAPReadWriteConnectionPool(
              @NotNull final LDAPConnection readConnection,
              final int initialReadConnections, final int maxReadConnections,
              @NotNull final LDAPConnection writeConnection,
              final int initialWriteConnections, final int maxWriteConnections)
         throws LDAPException
  {
    Validator.ensureNotNull(readConnection, writeConnection);
    Validator.ensureTrue(initialReadConnections >= 1,
         "LDAPReadWriteConnectionPool.initialReadConnections must be at " +
              "least 1.");
    Validator.ensureTrue(maxReadConnections >= initialReadConnections,
         "LDAPReadWriteConnectionPool.initialReadConnections must not be " +
              "greater than maxReadConnections.");
    Validator.ensureTrue(initialWriteConnections >= 1,
         "LDAPReadWriteConnectionPool.initialWriteConnections must be at " +
              "least 1.");
    Validator.ensureTrue(maxWriteConnections >= initialWriteConnections,
         "LDAPReadWriteConnectionPool.initialWriteConnections must not be " +
              "greater than maxWriteConnections.");

    readPool = new LDAPConnectionPool(readConnection, initialReadConnections,
                                      maxReadConnections);

    try
    {
      writePool = new LDAPConnectionPool(writeConnection,
           initialWriteConnections, maxWriteConnections);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      readPool.close();
      throw le;
    }
  }



  /**
   * Creates a new LDAP read-write connection pool with the provided pools for
   * read and write operations, respectively.
   *
   * @param  readPool   The connection pool to be used for read operations.  It
   *                    must not be {@code null}.
   * @param  writePool  The connection pool to be used for write operations.  It
   *                    must not be {@code null}.
   */
  public LDAPReadWriteConnectionPool(@NotNull final LDAPConnectionPool readPool,
              @NotNull final LDAPConnectionPool writePool)
  {
    Validator.ensureNotNull(readPool, writePool);

    this.readPool  = readPool;
    this.writePool = writePool;
  }



  /**
   * Closes this connection pool.  All read and write connections currently held
   * in the pool that are not in use will be closed, and any outstanding
   * connections will be automatically closed when they are released back to the
   * pool.
   */
  @Override()
  public void close()
  {
    readPool.close();
    writePool.close();
  }



  /**
   * Indicates whether this connection pool has been closed.
   *
   * @return  {@code true} if this connection pool has been closed, or
   *          {@code false} if not.
   */
  public boolean isClosed()
  {
    return readPool.isClosed() || writePool.isClosed();
  }



  /**
   * Retrieves an LDAP connection from the read pool.
   *
   * @return  The LDAP connection taken from the read pool.
   *
   * @throws  LDAPException  If no read connection is available, or a problem
   *                         occurs while creating a new connection to return.
   */
  @NotNull()
  public LDAPConnection getReadConnection()
         throws LDAPException
  {
    return readPool.getConnection();
  }



  /**
   * Releases the provided connection back to the read pool.
   *
   * @param  connection  The connection to be released back to the read pool.
   */
  public void releaseReadConnection(@NotNull final LDAPConnection connection)
  {
    readPool.releaseConnection(connection);
  }



  /**
   * Indicates that the provided read connection is no longer in use, but is
   * also no longer fit for use.  The provided connection will be terminated and
   * a new connection will be created and added to the read pool in its place.
   *
   * @param  connection  The defunct read connection being released.
   */
  public void releaseDefunctReadConnection(
                   @NotNull final LDAPConnection connection)
  {
    readPool.releaseDefunctConnection(connection);
  }



  /**
   * Retrieves an LDAP connection from the write pool.
   *
   * @return  The LDAP connection taken from the write pool.
   *
   * @throws  LDAPException  If no write connection is available, or a problem
   *                         occurs while creating a new connection to return.
   */
  @NotNull()
  public LDAPConnection getWriteConnection()
         throws LDAPException
  {
    return writePool.getConnection();
  }



  /**
   * Releases the provided connection back to the write pool.
   *
   * @param  connection  The connection to be released back to the write pool.
   */
  public void releaseWriteConnection(@NotNull final LDAPConnection connection)
  {
    writePool.releaseConnection(connection);
  }



  /**
   * Indicates that the provided write connection is no longer in use, but is
   * also no longer fit for use.  The provided connection will be terminated and
   * a new connection will be created and added to the write pool in its place.
   *
   * @param  connection  The defunct write connection being released.
   */
  public void releaseDefunctWriteConnection(
                   @NotNull final LDAPConnection connection)
  {
    writePool.releaseDefunctConnection(connection);
  }



  /**
   * Retrieves the set of statistics maintained for the read pool.
   *
   * @return  The set of statistics maintained for the read pool.
   */
  @NotNull()
  public LDAPConnectionPoolStatistics getReadPoolStatistics()
  {
    return readPool.getConnectionPoolStatistics();
  }



  /**
   * Retrieves the set of statistics maintained for the write pool.
   *
   * @return  The set of statistics maintained for the write pool.
   */
  @NotNull()
  public LDAPConnectionPoolStatistics getWritePoolStatistics()
  {
    return writePool.getConnectionPoolStatistics();
  }



  /**
   * Retrieves the connection pool that should be used for read operations.
   *
   * @return  The connection pool that should be used for read operations.
   */
  @NotNull()
  public LDAPConnectionPool getReadPool()
  {
    return readPool;
  }



  /**
   * Retrieves the connection pool that should be used for write operations.
   *
   * @return  The connection pool that should be used for write operations.
   */
  @NotNull()
  public LDAPConnectionPool getWritePool()
  {
    return writePool;
  }



  /**
   * Retrieves the directory server root DSE using a read connection from this
   * connection pool.
   *
   * @return  The directory server root DSE, or {@code null} if it is not
   *          available.
   *
   * @throws  LDAPException  If a problem occurs while attempting to retrieve
   *                         the server root DSE.
   */
  @Override()
  @Nullable()
  public RootDSE getRootDSE()
         throws LDAPException
  {
    return readPool.getRootDSE();
  }



  /**
   * Retrieves the directory server schema definitions using a read connection
   * from this connection pool, using the subschema subentry DN contained in the
   * server's root DSE.  For directory servers containing a single schema, this
   * should be sufficient for all purposes.  For servers with multiple schemas,
   * it may be necessary to specify the DN of the target entry for which to
   * obtain the associated schema.
   *
   * @return  The directory server schema definitions, or {@code null} if the
   *          schema information could not be retrieved (e.g, the client does
   *          not have permission to read the server schema).
   *
   * @throws  LDAPException  If a problem occurs while attempting to retrieve
   *                         the server schema.
   */
  @Override()
  @Nullable()
  public Schema getSchema()
         throws LDAPException
  {
    return readPool.getSchema();
  }



  /**
   * Retrieves the directory server schema definitions that govern the specified
   * entry using a read connection from this connection pool.  The
   * subschemaSubentry attribute will be retrieved from the target entry, and
   * then the appropriate schema definitions will be loaded from the entry
   * referenced by that attribute.  This may be necessary to ensure correct
   * behavior in servers that support multiple schemas.
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
  @Override()
  @Nullable()
  public Schema getSchema(@Nullable final String entryDN)
         throws LDAPException
  {
    return readPool.getSchema(entryDN);
  }



  /**
   * Retrieves the entry with the specified DN using a read connection from this
   * connection pool.  All user attributes will be requested in the entry to
   * return.
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
  @Override()
  @Nullable()
  public SearchResultEntry getEntry(@NotNull final String dn)
         throws LDAPException
  {
    return readPool.getEntry(dn);
  }



  /**
   * Retrieves the entry with the specified DN using a read connection from this
   * connection pool.
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
  @Override()
  @Nullable()
  public SearchResultEntry getEntry(@NotNull final String dn,
                                    @Nullable final String... attributes)
         throws LDAPException
  {
    return readPool.getEntry(dn, attributes);
  }



  /**
   * Processes an add operation with the provided information using a write
   * connection from this connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final String dn,
                        @NotNull final Attribute... attributes)
         throws LDAPException
  {
    return writePool.add(dn, attributes);
  }



  /**
   * Processes an add operation with the provided information using a write
   * connection from this connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final String dn,
                        @NotNull final Collection<Attribute> attributes)
         throws LDAPException
  {
    return writePool.add(dn, attributes);
  }



  /**
   * Processes an add operation with the provided information using a write
   * connection from this connection pool.
   *
   * @param  entry  The entry to add.  It must not be {@code null}.
   *
   * @return  The result of processing the add operation.
   *
   * @throws  LDAPException  If the server rejects the add request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final Entry entry)
         throws LDAPException
  {
    return writePool.add(entry);
  }



  /**
   * Processes an add operation with the provided information using a write
   * connection from this connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final String... ldifLines)
         throws LDIFException, LDAPException
  {
    return writePool.add(ldifLines);
  }



  /**
   * Processes the provided add request using a write connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final AddRequest addRequest)
         throws LDAPException
  {
    return writePool.add(addRequest);
  }



  /**
   * Processes the provided add request using a write connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult add(@NotNull final ReadOnlyAddRequest addRequest)
         throws LDAPException
  {
    return writePool.add((AddRequest) addRequest);
  }



  /**
   * Processes a simple bind request with the provided DN and password using a
   * read connection from this connection pool.  Note that this will impact the
   * state of the connection in the pool, and therefore this method should only
   * be used if this connection pool is used exclusively for processing bind
   * operations, or if the retain identity request control (a proprietary
   * control for use with the Ping Identity, UnboundID, or Nokia/Alcatel-Lucent
   * 8661 Directory Server) is included in the bind request to ensure that the
   * authentication state is not impacted.
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
    return readPool.bind(bindDN, password);
  }



  /**
   * Processes the provided bind request using a read connection from this
   * connection pool.  Note that this will impact the state of the connection in
   * the pool, and therefore this method should only be used if this connection
   * pool is used exclusively for processing bind operations, or if the retain
   * identity request control (a proprietary control for use with the Ping
   * Identity, UnboundID, or Nokia/Alcatel-Lucent 8661 Directory Server) is
   * included in the bind request to ensure that the authentication state is not
   * impacted.
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
    return readPool.bind(bindRequest);
  }



  /**
   * Processes a compare operation with the provided information using a read
   * connection from this connection pool.
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
  @Override()
  @NotNull()
  public CompareResult compare(@NotNull final String dn,
                               @NotNull final String attributeName,
                               @NotNull final String assertionValue)
         throws LDAPException
  {
    return readPool.compare(dn, attributeName, assertionValue);
  }



  /**
   * Processes the provided compare request using a read connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public CompareResult compare(@NotNull final CompareRequest compareRequest)
         throws LDAPException
  {
    return readPool.compare(compareRequest);
  }



  /**
   * Processes the provided compare request using a read connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public CompareResult compare(
              @NotNull final ReadOnlyCompareRequest compareRequest)
         throws LDAPException
  {
    return readPool.compare(compareRequest);
  }



  /**
   * Deletes the entry with the specified DN using a write connection from this
   * connection pool.
   *
   * @param  dn  The DN of the entry to delete.  It must not be {@code null}.
   *
   * @return  The result of processing the delete operation.
   *
   * @throws  LDAPException  If the server rejects the delete request, or if a
   *                         problem is encountered while sending the request or
   *                         reading the response.
   */
  @Override()
  @NotNull()
  public LDAPResult delete(@NotNull final String dn)
         throws LDAPException
  {
    return writePool.delete(dn);
  }



  /**
   * Processes the provided delete request using a write connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult delete(@NotNull final DeleteRequest deleteRequest)
         throws LDAPException
  {
    return writePool.delete(deleteRequest);
  }



  /**
   * Processes the provided delete request using a write connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult delete(@NotNull final ReadOnlyDeleteRequest deleteRequest)
         throws LDAPException
  {
    return writePool.delete(deleteRequest);
  }



  /**
   * Applies the provided modification to the specified entry using a write
   * connection from this connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String dn,
                           @NotNull final Modification mod)
         throws LDAPException
  {
    return writePool.modify(dn, mod);
  }



  /**
   * Applies the provided set of modifications to the specified entry using a
   * write connection from this connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String dn,
                           @NotNull final Modification... mods)
         throws LDAPException
  {
    return writePool.modify(dn, mods);
  }



  /**
   * Applies the provided set of modifications to the specified entry using a
   * write connection from this connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String dn,
                           @NotNull final List<Modification> mods)
         throws LDAPException
  {
    return writePool.modify(dn, mods);
  }



  /**
   * Processes a modify request from the provided LDIF representation of the
   * changes using a write connection from this connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final String... ldifModificationLines)
         throws LDIFException, LDAPException
  {
    return writePool.modify(ldifModificationLines);
  }



  /**
   * Processes the provided modify request using a write connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final ModifyRequest modifyRequest)
         throws LDAPException
  {
    return writePool.modify(modifyRequest);
  }



  /**
   * Processes the provided modify request using a write connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult modify(@NotNull final ReadOnlyModifyRequest modifyRequest)
         throws LDAPException
  {
    return writePool.modify(modifyRequest);
  }



  /**
   * Performs a modify DN operation with the provided information using a write
   * connection from this connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult modifyDN(@NotNull final String dn,
                             @NotNull final String newRDN,
                             final boolean deleteOldRDN)
         throws LDAPException
  {
    return writePool.modifyDN(dn, newRDN, deleteOldRDN);
  }



  /**
   * Performs a modify DN operation with the provided information using a write
   * connection from this connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult modifyDN(@NotNull final String dn,
                             @NotNull final String newRDN,
                             final boolean deleteOldRDN,
                             @Nullable final String newSuperiorDN)
         throws LDAPException
  {
    return writePool.modifyDN(dn, newRDN, deleteOldRDN, newSuperiorDN);
  }



  /**
   * Processes the provided modify DN request using a write connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult modifyDN(@NotNull final ModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return writePool.modifyDN(modifyDNRequest);
  }



  /**
   * Processes the provided modify DN request using a write connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public LDAPResult modifyDN(
              @NotNull final ReadOnlyModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return writePool.modifyDN(modifyDNRequest);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.  The search result entries and
   * references will be collected internally and included in the
   * {@code SearchResult} object that is returned.
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
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final String baseDN,
                             @NotNull final SearchScope scope,
                             @NotNull final String filter,
                             @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(baseDN, scope, filter, attributes);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.  The search result entries and
   * references will be collected internally and included in the
   * {@code SearchResult} object that is returned.
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
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final String baseDN,
                             @NotNull final SearchScope scope,
                             @NotNull final Filter filter,
                             @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(baseDN, scope, filter, attributes);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.
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
  @Override()
  @NotNull()
  public SearchResult search(
              @Nullable final SearchResultListener searchResultListener,
              @NotNull final String baseDN, @NotNull final SearchScope scope,
              @NotNull final String filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(searchResultListener, baseDN, scope, filter,
                           attributes);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.
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
  @Override()
  @NotNull()
  public SearchResult search(
              @Nullable final SearchResultListener searchResultListener,
              @NotNull final String baseDN, @NotNull final SearchScope scope,
              @NotNull final Filter filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return readPool.search(searchResultListener, baseDN, scope, filter,
                           attributes);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.  The search result entries and
   * references will be collected internally and included in the
   * {@code SearchResult} object that is returned.
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
    return readPool.search(baseDN, scope, derefPolicy, sizeLimit, timeLimit,
                           typesOnly, filter, attributes);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.  The search result entries and
   * references will be collected internally and included in the
   * {@code SearchResult} object that is returned.
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
    return readPool.search(baseDN, scope, derefPolicy, sizeLimit, timeLimit,
                           typesOnly, filter, attributes);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.
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
    return readPool.search(searchResultListener, baseDN, scope, derefPolicy,
                           sizeLimit, timeLimit, typesOnly, filter, attributes);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.
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
    return readPool.search(searchResultListener, baseDN, scope, derefPolicy,
                           sizeLimit, timeLimit, typesOnly, filter, attributes);
  }



  /**
   * Processes the provided search request using a read connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    return readPool.search(searchRequest);
  }



  /**
   * Processes the provided search request using a read connection from this
   * connection pool.
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
  @Override()
  @NotNull()
  public SearchResult search(@NotNull final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return readPool.search(searchRequest);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.  It is expected that at most one
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
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(@NotNull final String baseDN,
                                          @NotNull final SearchScope scope,
                                          @NotNull final String filter,
                                          @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return readPool.searchForEntry(baseDN, scope, filter, attributes);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.  It is expected that at most one
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
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(@NotNull final String baseDN,
                                          @NotNull final SearchScope scope,
                                          @NotNull final Filter filter,
                                          @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return readPool.searchForEntry(baseDN, scope, filter, attributes);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.  It is expected that at most one
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
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(
              @NotNull final String baseDN, @NotNull final SearchScope scope,
              @NotNull final DereferencePolicy derefPolicy, final int timeLimit,
              final boolean typesOnly, @NotNull final String filter,
              @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return readPool.searchForEntry(baseDN, scope, derefPolicy, timeLimit,
         typesOnly, filter, attributes);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.  It is expected that at most one
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
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(@NotNull final String baseDN,
              @NotNull final SearchScope scope,
              @NotNull final DereferencePolicy derefPolicy, final int timeLimit,
              final boolean typesOnly, @NotNull final Filter filter,
              @Nullable final String... attributes)
       throws LDAPSearchException
  {
    return readPool.searchForEntry(baseDN, scope, derefPolicy, timeLimit,
         typesOnly, filter, attributes);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.  It is expected that at most one
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
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(
              @NotNull final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    return readPool.searchForEntry(searchRequest);
  }



  /**
   * Processes a search operation with the provided information using a read
   * connection from this connection pool.  It is expected that at most one
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
  @Override()
  @Nullable()
  public SearchResultEntry searchForEntry(
              @NotNull final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return readPool.searchForEntry(searchRequest);
  }



  /**
   * Closes this connection pool in the event that it becomes unreferenced.
   *
   * @throws  Throwable  If an unexpected problem occurs.
   */
  @Override()
  protected void finalize()
            throws Throwable
  {
    super.finalize();

    close();
  }
}
