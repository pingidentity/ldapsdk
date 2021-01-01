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
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides the base class for LDAP connection pool implementations
 * provided by the LDAP SDK for Java.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class AbstractConnectionPool
       implements FullLDAPInterface, Closeable
{
  /**
   * Closes this connection pool.  All connections currently held in the pool
   * that are not in use will be closed, and any outstanding connections will be
   * automatically closed when they are released back to the pool.
   */
  @Override()
  public abstract void close();



  /**
   * Closes this connection pool, optionally using multiple threads to close the
   * connections in parallel.
   *
   * @param  unbind      Indicates whether to try to send an unbind request to
   *                     the server before closing the connection.
   * @param  numThreads  The number of threads to use when closing the
   *                     connections.
   */
  public abstract void close(boolean unbind, int numThreads);



  /**
   * Indicates whether this connection pool has been closed.
   *
   * @return  {@code true} if this connection pool has been closed, or
   *          {@code false} if not.
   */
  public abstract boolean isClosed();



  /**
   * Retrieves an LDAP connection from the pool.
   *
   * @return  The LDAP connection taken from the pool.
   *
   * @throws  LDAPException  If no connection is available, or a problem occurs
   *                         while creating a new connection to return.
   */
  @NotNull()
  public abstract LDAPConnection getConnection()
         throws LDAPException;



  /**
   * Releases the provided connection back to this pool.
   *
   * @param  connection  The connection to be released back to the pool.
   */
  public abstract void releaseConnection(@NotNull LDAPConnection connection);



  /**
   * Indicates that the provided connection is no longer in use, but is also no
   * longer fit for use.  The provided connection will be terminated and a new
   * connection will be created and added to the pool in its place.
   *
   * @param  connection  The defunct connection being released.
   */
  public abstract void releaseDefunctConnection(
                            @NotNull LDAPConnection connection);



  /**
   * Releases the provided connection back to the pool after an exception has
   * been encountered while processing an operation on that connection.  The
   * connection pool health check instance associated with this pool will be
   * used to determine whether the provided connection is still valid and will
   * either release it back for use in processing other operations on the
   * connection or will terminate the connection and create a new one to take
   * its place.
   *
   * @param  connection  The connection to be evaluated and released back to the
   *                     pool or replaced with a new connection.
   * @param  exception   The exception caught while processing an operation on
   *                     the connection.
   */
  public final void releaseConnectionAfterException(
                         @NotNull final LDAPConnection connection,
                         @NotNull final LDAPException exception)
  {
    final LDAPConnectionPoolHealthCheck healthCheck = getHealthCheck();

    try
    {
      healthCheck.ensureConnectionValidAfterException(connection, exception);
      releaseConnection(connection);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      releaseDefunctConnection(connection);
    }
  }



  /**
   * Releases the provided connection as defunct and creates a new connection to
   * replace it, if possible, optionally connected to a different directory
   * server instance than the instance with which the original connection was
   * established.
   *
   * @param  connection  The defunct connection to be replaced.
   *
   * @return  The newly-created connection intended to replace the provided
   *          connection.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the new connection.  Note that even if an exception
   *                         is thrown, then the provided connection must have
   *                         been properly released as defunct.
   */
  @NotNull()
  public abstract LDAPConnection replaceDefunctConnection(
                                      @NotNull LDAPConnection connection)
         throws LDAPException;



  /**
   * Attempts to replace the provided connection.  However, if an exception is
   * encountered while obtaining the new connection then an exception will be
   * thrown based on the provided {@code Throwable} object.
   *
   * @param  t           The {@code Throwable} that was caught and prompted the
   *                     connection to be replaced.
   * @param  connection  The defunct connection to be replaced.
   *
   * @return  The newly-created connection intended to replace the provided
   *          connection.
   *
   * @throws  LDAPException  If an exception is encountered while attempting to
   *                         obtain the new connection.  Note that this
   *                         exception will be generated from the provided
   *                         {@code Throwable} rather than based on the
   *                         exception caught while trying to create the new
   *                         connection.
   */
  @NotNull()
  private LDAPConnection replaceDefunctConnection(@NotNull final Throwable t,
                              @NotNull final LDAPConnection connection)
          throws LDAPException
  {
    try
    {
      return replaceDefunctConnection(connection);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      if (t instanceof LDAPException)
      {
        throw (LDAPException) t;
      }
      else
      {
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_POOL_OP_EXCEPTION.get(StaticUtils.getExceptionMessage(t)), t);
      }
    }
  }



  /**
   * Indicates whether attempts to process operations should be retried on a
   * newly-created connection if the initial attempt fails in a manner that
   * indicates that the connection used to process that request may no longer
   * be valid.  Only a single retry will be attempted for any operation.
   * <BR><BR>
   * Note that this only applies to methods used to process operations in the
   * context pool (e.g., using methods that are part of {@link LDAPInterface}),
   * and will not automatically be used for operations processed on connections
   * checked out of the pool.
   * <BR><BR>
   * This method is provided for the purpose of backward compatibility, but new
   * functionality has been added to control retry on a per-operation-type
   * basis via the {@link #setRetryFailedOperationsDueToInvalidConnections(Set)}
   * method.  If retry is enabled for any operation type, then this method will
   * return {@code true}, and it will only return {@code false} if retry should
   * not be used for any operation type.  To determine the operation types for
   * which failed operations may be retried, use the
   * {@link #getOperationTypesToRetryDueToInvalidConnections()}  method.
   *
   * @return  {@code true} if the connection pool should attempt to retry
   *          operations on a newly-created connection if they fail in a way
   *          that indicates the associated connection may no longer be usable,
   *          or {@code false} if operations should only be attempted once.
   */
  public final boolean retryFailedOperationsDueToInvalidConnections()
  {
    return (! getOperationTypesToRetryDueToInvalidConnections().isEmpty());
  }



  /**
   * Retrieves the set of operation types for which operations should be
   * retried if the initial attempt fails in a manner that indicates that the
   * connection used to process the request may no longer be valid.
   *
   * @return  The set of operation types for which operations should be
   *          retried if the initial attempt fails in a manner that indicates
   *          that the connection used to process the request may no longer be
   *          valid, or an empty set if retries should not be performed for any
   *          type of operation.
   */
  @NotNull()
  public abstract Set<OperationType>
              getOperationTypesToRetryDueToInvalidConnections();



  /**
   * Specifies whether attempts to process operations should be retried on a
   * newly-created connection if the initial attempt fails in a manner that
   * indicates that the connection used to process that request may no longer
   * be valid.  Only a single retry will be attempted for any operation.
   * <BR><BR>
   * Note that this only applies to methods used to process operations in the
   * context pool (e.g., using methods that are part of {@link LDAPInterface}),
   * and will not automatically be used for operations processed on connections
   * checked out of the pool.
   * <BR><BR>
   * This method is provided for the purpose of backward compatibility, but new
   * functionality has been added to control retry on a per-operation-type
   * basis via the {@link #setRetryFailedOperationsDueToInvalidConnections(Set)}
   * method.  If this is called with a value of {@code true}, then retry will be
   * enabled for all types of operations.  If it is called with a value of
   * {@code false}, then retry will be disabled for all types of operations.
   *
   * @param  retryFailedOperationsDueToInvalidConnections
   *              Indicates whether attempts to process operations should be
   *              retried on a newly-created connection if they fail in a way
   *              that indicates the associated connection may no longer be
   *              usable.
   */
  public final void setRetryFailedOperationsDueToInvalidConnections(
              final boolean retryFailedOperationsDueToInvalidConnections)
  {
    if (retryFailedOperationsDueToInvalidConnections)
    {
      setRetryFailedOperationsDueToInvalidConnections(
           EnumSet.allOf(OperationType.class));
    }
    else
    {
      setRetryFailedOperationsDueToInvalidConnections(
           EnumSet.noneOf(OperationType.class));
    }
  }



  /**
   * Specifies the types of operations that should be retried on a newly-created
   * connection if the initial attempt fails in a manner that indicates that
   * the connection used to process the request may no longer be valid.  Only a
   * single retry will be attempted for any operation.
   * <BR><BR>
   * Note that this only applies to methods used to process operations in the
   * context pool (e.g., using methods that are part of {@link LDAPInterface}),
   * and will not automatically be used for operations processed on connections
   * checked out of the pool.
   *
   * @param  operationTypes  The types of operations for which to retry failed
   *                         operations if they fail in a way that indicates the
   *                         associated connection may no longer be usable.  It
   *                         may be {@code null} or empty to indicate that no
   *                         types of operations should be retried.
   */
  public abstract void setRetryFailedOperationsDueToInvalidConnections(
                            @Nullable Set<OperationType> operationTypes);



  /**
   * Retrieves the number of connections that are currently available for use in
   * this connection pool, if applicable.
   *
   * @return  The number of connections that are currently available for use in
   *          this connection pool, or -1 if that is not applicable for this
   *          type of connection pool.
   */
  public abstract int getCurrentAvailableConnections();



  /**
   * Retrieves the maximum number of connections to be maintained in this
   * connection pool, which is the maximum number of available connections that
   * should be available at any time, if applicable.
   *
   * @return  The number of connections to be maintained in this connection
   *          pool, or -1 if that is not applicable for this type of connection
   *          pool.
   */
  public abstract int getMaximumAvailableConnections();



  /**
   * Retrieves the set of statistics maintained for this LDAP connection pool.
   *
   * @return  The set of statistics maintained for this LDAP connection pool.
   */
  @NotNull()
  public abstract LDAPConnectionPoolStatistics getConnectionPoolStatistics();



  /**
   * Retrieves the user-friendly name that has been assigned to this connection
   * pool.
   *
   * @return  The user-friendly name that has been assigned to this connection
   *          pool, or {@code null} if none has been assigned.
   */
  @Nullable()
  public abstract String getConnectionPoolName();



  /**
   * Specifies the user-friendly name that should be used for this connection
   * pool.  This name may be used in debugging to help identify the purpose of
   * this connection pool.  It will also be assigned to all connections
   * associated with this connection pool.
   *
   * @param  connectionPoolName  The user-friendly name that should be used for
   *                             this connection pool.
   */
  public abstract void setConnectionPoolName(
                            @Nullable String connectionPoolName);



  /**
   * Retrieves the health check implementation for this connection pool.
   *
   * @return  The health check implementation for this connection pool.
   */
  @NotNull()
  public abstract LDAPConnectionPoolHealthCheck getHealthCheck();



  /**
   * Retrieves the length of time in milliseconds between periodic background
   * health checks against the available connections in this pool.
   *
   * @return  The length of time in milliseconds between the periodic background
   *          health checks against the available connections in this pool.
   */
  public abstract long getHealthCheckIntervalMillis();



  /**
   * Specifies the length of time in milliseconds between periodic background
   * health checks against the available connections in this pool.
   *
   * @param  healthCheckInterval  The length of time in milliseconds between
   *                              periodic background health checks against the
   *                              available connections in this pool.  The
   *                              provided value must be greater than zero.
   */
  public abstract void setHealthCheckIntervalMillis(long healthCheckInterval);



  /**
   * Performs a health check against all connections currently available in this
   * connection pool.  This should only be invoked by the connection pool health
   * check thread.
   */
  protected abstract void doHealthCheck();



  /**
   * Retrieves the directory server root DSE using a connection from this
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
  public final RootDSE getRootDSE()
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final RootDSE rootDSE = conn.getRootDSE();
      releaseConnection(conn);
      return rootDSE;
    }
    catch (final Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.SEARCH, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final RootDSE rootDSE = newConn.getRootDSE();
        releaseConnection(newConn);
        return rootDSE;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Retrieves the directory server schema definitions using a connection from
   * this connection pool, using the subschema subentry DN contained in the
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
  public final Schema getSchema()
         throws LDAPException
  {
    return getSchema("");
  }



  /**
   * Retrieves the directory server schema definitions that govern the specified
   * entry using a connection from this connection pool.  The subschemaSubentry
   * attribute will be retrieved from the target entry, and then the appropriate
   * schema definitions will be loaded from the entry referenced by that
   * attribute.  This may be necessary to ensure correct behavior in servers
   * that support multiple schemas.
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
  public final Schema getSchema(@Nullable final String entryDN)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final Schema schema = conn.getSchema(entryDN);
      releaseConnection(conn);
      return schema;
    }
    catch (final Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.SEARCH, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final Schema schema = newConn.getSchema(entryDN);
        releaseConnection(newConn);
        return schema;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Retrieves the entry with the specified DN using a connection from this
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
  public final SearchResultEntry getEntry(@NotNull final String dn)
         throws LDAPException
  {
    return getEntry(dn, StaticUtils.NO_STRINGS);
  }



  /**
   * Retrieves the entry with the specified DN using a connection from this
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
  public final SearchResultEntry getEntry(@NotNull final String dn,
                                          @Nullable final String... attributes)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final SearchResultEntry entry = conn.getEntry(dn, attributes);
      releaseConnection(conn);
      return entry;
    }
    catch (final Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.SEARCH, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final SearchResultEntry entry = newConn.getEntry(dn, attributes);
        releaseConnection(newConn);
        return entry;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes an add operation with the provided information using a connection
   * from this connection pool.
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
  public final LDAPResult add(@NotNull final String dn,
                              @NotNull final Attribute... attributes)
         throws LDAPException
  {
    return add(new AddRequest(dn, attributes));
  }



  /**
   * Processes an add operation with the provided information using a connection
   * from this connection pool.
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
  public final LDAPResult add(@NotNull final String dn,
                              @NotNull final Collection<Attribute> attributes)
         throws LDAPException
  {
    return add(new AddRequest(dn, attributes));
  }



  /**
   * Processes an add operation with the provided information using a connection
   * from this connection pool.
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
  public final LDAPResult add(@NotNull final Entry entry)
         throws LDAPException
  {
    return add(new AddRequest(entry));
  }



  /**
   * Processes an add operation with the provided information using a connection
   * from this connection pool.
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
  public final LDAPResult add(@NotNull final String... ldifLines)
         throws LDIFException, LDAPException
  {
    return add(new AddRequest(ldifLines));
  }



  /**
   * Processes the provided add request using a connection from this connection
   * pool.
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
  public final LDAPResult add(@NotNull final AddRequest addRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.add(addRequest);
      releaseConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.ADD, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final LDAPResult result = newConn.add(addRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes the provided add request using a connection from this connection
   * pool.
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
  public final LDAPResult add(@NotNull final ReadOnlyAddRequest addRequest)
         throws LDAPException
  {
    return add((AddRequest) addRequest);
  }



  /**
   * Processes a simple bind request with the provided DN and password using a
   * connection from this connection pool.  Note that this will impact the state
   * of the connection in the pool, and therefore this method should only be
   * used if this connection pool is used exclusively for processing bind
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
  public final BindResult bind(@Nullable final String bindDN,
                               @Nullable final String password)
         throws LDAPException
  {
    return bind(new SimpleBindRequest(bindDN, password));
  }



  /**
   * Processes the provided bind request using a connection from this connection
   * pool.  Note that this will impact the state of the connection in the pool,
   * and therefore this method should only be used if this connection pool is
   * used exclusively for processing bind operations, or if the retain identity
   * request control (a proprietary control for use with the Ping Identity,
   * UnboundID, or Nokia/Alcatel-Lucent 8661 Directory Server) is included in
   * the bind request to ensure that the authentication state is not impacted.
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
  @NotNull
  public final BindResult bind(@NotNull final BindRequest bindRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final BindResult result = conn.bind(bindRequest);
      releaseConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.BIND, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final BindResult result = newConn.bind(bindRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes a compare operation with the provided information using a
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
  public final CompareResult compare(@NotNull final String dn,
                                     @NotNull final String attributeName,
                                     @NotNull final String assertionValue)
         throws LDAPException
  {
    return compare(new CompareRequest(dn, attributeName, assertionValue));
  }



  /**
   * Processes the provided compare request using a connection from this
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
  public final CompareResult compare(
                                  @NotNull final CompareRequest compareRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final CompareResult result = conn.compare(compareRequest);
      releaseConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.COMPARE, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final CompareResult result = newConn.compare(compareRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes the provided compare request using a connection from this
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
  public final CompareResult compare(
                    @NotNull final ReadOnlyCompareRequest compareRequest)
         throws LDAPException
  {
    return compare((CompareRequest) compareRequest);
  }



  /**
   * Deletes the entry with the specified DN using a connection from this
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
  public final LDAPResult delete(@NotNull final String dn)
         throws LDAPException
  {
    return delete(new DeleteRequest(dn));
  }



  /**
   * Processes the provided delete request using a connection from this
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
  public final LDAPResult delete(@NotNull final DeleteRequest deleteRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.delete(deleteRequest);
      releaseConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.DELETE, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final LDAPResult result = newConn.delete(deleteRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes the provided delete request using a connection from this
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
  public final LDAPResult delete(
                    @NotNull final ReadOnlyDeleteRequest deleteRequest)
         throws LDAPException
  {
    return delete((DeleteRequest) deleteRequest);
  }



  /**
   * Processes an extended operation with the provided request OID using a
   * connection from this connection pool.  Note that this method should not be
   * used to perform any operation that will alter the state of the connection
   * in the pool (e.g., a StartTLS operation) or that involves multiple
   * distinct operations on the same connection (e.g., LDAP transactions).
   *
   * @param  requestOID  The OID for the extended request to process.  It must
   *                     not be {@code null}.
   *
   * @return  The extended result object that provides information about the
   *          result of the request processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @NotNull()
  public final ExtendedResult processExtendedOperation(
                                   @NotNull final String requestOID)
         throws LDAPException
  {
    return processExtendedOperation(new ExtendedRequest(requestOID));
  }



  /**
   * Processes an extended operation with the provided request OID and value
   * using a connection from this connection pool.  Note that this method should
   * not be used to perform any operation that will alter the state of the
   * connection in the pool (e.g., a StartTLS operation) or that involves
   * multiple distinct operations on the same connection (e.g., LDAP
   * transactions).
   *
   * @param  requestOID    The OID for the extended request to process.  It must
   *                       not be {@code null}.
   * @param  requestValue  The encoded value for the extended request to
   *                       process.  It may be {@code null} if there does not
   *                       need to be a value for the requested operation.
   *
   * @return  The extended result object that provides information about the
   *          result of the request processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @NotNull()
  public final ExtendedResult processExtendedOperation(
                                   @NotNull final String requestOID,
                                   @Nullable final ASN1OctetString requestValue)
         throws LDAPException
  {
    return processExtendedOperation(new ExtendedRequest(requestOID,
         requestValue));
  }



  /**
   * Processes the provided extended request using a connection from this
   * connection pool.  Note that this method should not be used to perform any
   * operation that will alter the state of the connection in the pool (e.g., a
   * StartTLS operation) or that involves multiple distinct operations on the
   * same connection (e.g., LDAP transactions).
   *
   * @param  extendedRequest  The extended request to be processed.  It must not
   *                          be {@code null}.
   *
   * @return  The extended result object that provides information about the
   *          result of the request processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @NotNull()
  public final ExtendedResult processExtendedOperation(
                    @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    if (extendedRequest.getOID().equals(
         StartTLSExtendedRequest.STARTTLS_REQUEST_OID))
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
                              ERR_POOL_STARTTLS_NOT_ALLOWED.get());
    }

    final LDAPConnection conn = getConnection();

    try
    {
      final ExtendedResult result =
           conn.processExtendedOperation(extendedRequest);
      releaseConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.EXTENDED, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final ExtendedResult result =
             newConn.processExtendedOperation(extendedRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Applies the provided modification to the specified entry using a connection
   * from this connection pool.
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
  public final LDAPResult modify(@NotNull final String dn,
                                 @NotNull final Modification mod)
         throws LDAPException
  {
    return modify(new ModifyRequest(dn, mod));
  }



  /**
   * Applies the provided set of modifications to the specified entry using a
   * connection from this connection pool.
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
  public final LDAPResult modify(@NotNull final String dn,
                                 @NotNull final Modification... mods)
         throws LDAPException
  {
    return modify(new ModifyRequest(dn, mods));
  }



  /**
   * Applies the provided set of modifications to the specified entry using a
   * connection from this connection pool.
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
  public final LDAPResult modify(@NotNull final String dn,
                                 @NotNull final List<Modification> mods)
         throws LDAPException
  {
    return modify(new ModifyRequest(dn, mods));
  }



  /**
   * Processes a modify request from the provided LDIF representation of the
   * changes using a connection from this connection pool.
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
  public final LDAPResult modify(@NotNull final String... ldifModificationLines)
         throws LDIFException, LDAPException
  {
    return modify(new ModifyRequest(ldifModificationLines));
  }



  /**
   * Processes the provided modify request using a connection from this
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
  public final LDAPResult modify(@NotNull final ModifyRequest modifyRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.modify(modifyRequest);
      releaseConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.MODIFY, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final LDAPResult result = newConn.modify(modifyRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes the provided modify request using a connection from this
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
  public final LDAPResult modify(
                    @NotNull final ReadOnlyModifyRequest modifyRequest)
         throws LDAPException
  {
    return modify((ModifyRequest) modifyRequest);
  }



  /**
   * Performs a modify DN operation with the provided information using a
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
  public final LDAPResult modifyDN(@NotNull final String dn,
                                   @NotNull final String newRDN,
                                   final boolean deleteOldRDN)
         throws LDAPException
  {
    return modifyDN(new ModifyDNRequest(dn, newRDN, deleteOldRDN));
  }



  /**
   * Performs a modify DN operation with the provided information using a
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
  public final LDAPResult modifyDN(@NotNull final String dn,
                                   @NotNull final String newRDN,
                                   final boolean deleteOldRDN,
                                   @Nullable final String newSuperiorDN)
         throws LDAPException
  {
    return modifyDN(new ModifyDNRequest(dn, newRDN, deleteOldRDN,
         newSuperiorDN));
  }



  /**
   * Processes the provided modify DN request using a connection from this
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
  public final LDAPResult modifyDN(
                    @NotNull final ModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.modifyDN(modifyDNRequest);
      releaseConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      throwLDAPExceptionIfShouldNotRetry(t, OperationType.MODIFY_DN, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn = replaceDefunctConnection(t, conn);

      try
      {
        final LDAPResult result = newConn.modifyDN(modifyDNRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes the provided modify DN request using a connection from this
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
  public final LDAPResult modifyDN(
                    @NotNull final ReadOnlyModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return modifyDN((ModifyDNRequest) modifyDNRequest);
  }



  /**
   * Processes a search operation with the provided information using a
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
   *                               request, or reading the response.  If one or
   *                               more entries or references were returned
   *                               before the failure was encountered, then the
   *                               {@code LDAPSearchException} object may be
   *                               examined to obtain information about those
   *                               entries and/or references.
   */
  @Override()
  @NotNull()
  public final SearchResult search(@NotNull final String baseDN,
                                   @NotNull final SearchScope scope,
                                   @NotNull final String filter,
                                   @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(baseDN, scope, parseFilter(filter),
         attributes));
  }



  /**
   * Processes a search operation with the provided information using a
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
  public final SearchResult search(@NotNull final String baseDN,
                                   @NotNull final SearchScope scope,
                                   @NotNull final Filter filter,
                                   @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(baseDN, scope, filter, attributes));
  }



  /**
   * Processes a search operation with the provided information using a
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
  public final SearchResult search(
       @Nullable final SearchResultListener searchResultListener,
       @NotNull final String baseDN, @NotNull final SearchScope scope,
       @NotNull final String filter, @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         parseFilter(filter), attributes));
  }



  /**
   * Processes a search operation with the provided information using a
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
  public final SearchResult search(
       @Nullable final SearchResultListener searchResultListener,
       @NotNull final String baseDN, @NotNull final SearchScope scope,
       @NotNull final Filter filter, @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         filter, attributes));
  }



  /**
   * Processes a search operation with the provided information using a
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
  public final SearchResult search(@NotNull final String baseDN,
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
   * Processes a search operation with the provided information using a
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
  public final SearchResult search(@NotNull final String baseDN,
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
   * Processes a search operation with the provided information using a
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
  public final SearchResult search(
       @Nullable final SearchResultListener searchResultListener,
       @NotNull final String baseDN, @NotNull final SearchScope scope,
       @NotNull final DereferencePolicy derefPolicy, final int sizeLimit,
       final int timeLimit, final boolean typesOnly,
       @NotNull final String filter, @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         derefPolicy, sizeLimit, timeLimit, typesOnly, parseFilter(filter),
         attributes));
  }



  /**
   * Processes a search operation with the provided information using a
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
  public final SearchResult search(
       @Nullable final SearchResultListener searchResultListener,
       @NotNull final String baseDN, @NotNull final SearchScope scope,
       @NotNull final DereferencePolicy derefPolicy, final int sizeLimit,
       final int timeLimit, final boolean typesOnly,
       @NotNull final Filter filter, @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return search(new SearchRequest(searchResultListener, baseDN, scope,
         derefPolicy, sizeLimit, timeLimit, typesOnly, filter, attributes));
  }



  /**
   * Processes the provided search request using a connection from this
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
  public final SearchResult search(@NotNull final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResult result = conn.search(searchRequest);
      releaseConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      throwLDAPSearchExceptionIfShouldNotRetry(t, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn;
      try
      {
        newConn = replaceDefunctConnection(t, conn);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        throw new LDAPSearchException(le);
      }

      try
      {
        final SearchResult result = newConn.search(searchRequest);
        releaseConnection(newConn);
        return result;
      }
      catch (final Throwable t2)
      {
        throwLDAPSearchException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes the provided search request using a connection from this
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
  public final SearchResult search(
                    @NotNull final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return search((SearchRequest) searchRequest);
  }



  /**
   * Processes a search operation with the provided information using a
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
  public final SearchResultEntry searchForEntry(@NotNull final String baseDN,
                                      @NotNull final SearchScope scope,
                                      @NotNull final String filter,
                                      @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope,
         DereferencePolicy.NEVER, 1, 0, false, parseFilter(filter),
         attributes));
  }



  /**
   * Processes a search operation with the provided information using a
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
  public final SearchResultEntry searchForEntry(@NotNull final String baseDN,
                                      @NotNull final SearchScope scope,
                                      @NotNull final Filter filter,
                                      @Nullable final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope,
         DereferencePolicy.NEVER, 1, 0, false, filter, attributes));
  }



  /**
   * Processes a search operation with the provided information using a
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
  public final SearchResultEntry searchForEntry(@NotNull final String baseDN,
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
   * Processes a search operation with the provided information using a
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
  public final SearchResultEntry searchForEntry(
                    @NotNull final String baseDN,
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
   * Processes a search operation with the provided information using a
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
  public final SearchResultEntry searchForEntry(
                    @NotNull final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResultEntry entry = conn.searchForEntry(searchRequest);
      releaseConnection(conn);
      return entry;
    }
    catch (final Throwable t)
    {
      throwLDAPSearchExceptionIfShouldNotRetry(t, conn);

      // If we have gotten here, then we should retry the operation with a
      // newly-created connection.
      final LDAPConnection newConn;
      try
      {
        newConn = replaceDefunctConnection(t, conn);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        throw new LDAPSearchException(le);
      }

      try
      {
        final SearchResultEntry entry = newConn.searchForEntry(searchRequest);
        releaseConnection(newConn);
        return entry;
      }
      catch (final Throwable t2)
      {
        throwLDAPSearchException(t2, newConn);
      }

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes a search operation with the provided information using a
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
  public final SearchResultEntry searchForEntry(
                    @NotNull final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return searchForEntry((SearchRequest) searchRequest);
  }



  /**
   * Parses the provided string as a {@code Filter} object.
   *
   * @param  filterString  The string to parse as a {@code Filter}.
   *
   * @return  The parsed {@code Filter}.
   *
   * @throws  LDAPSearchException  If the provided string does not represent a
   *                               valid search filter.
   */
  @NotNull()
  private static Filter parseFilter(@NotNull final String filterString)
          throws LDAPSearchException
  {
    try
    {
      return Filter.create(filterString);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPSearchException(le);
    }
  }



  /**
   * Processes multiple requests in the order they are provided over a single
   * connection from this pool.  Note that the
   * {@link #retryFailedOperationsDueToInvalidConnections()} setting will be
   * ignored when processing the provided operations, so that any failed
   * operations will not be retried.
   *
   * @param  requests         The list of requests to be processed.  It must not
   *                          be {@code null} or empty.
   * @param  continueOnError  Indicates whether to attempt to process subsequent
   *                          requests if any of the operations does not
   *                          complete successfully.
   *
   * @return  The set of results from the requests that were processed.  The
   *          order of result objects will correspond to the order of the
   *          request objects, although the list of results may contain fewer
   *          elements than the list of requests if an error occurred during
   *          processing and {@code continueOnError} is {@code false}.
   *
   * @throws  LDAPException  If a problem occurs while trying to obtain a
   *                         connection to use for the requests.
   */
  @NotNull()
  public final List<LDAPResult> processRequests(
                                     @NotNull final List<LDAPRequest> requests,
                                     final boolean continueOnError)
         throws LDAPException
  {
    Validator.ensureNotNull(requests);
    Validator.ensureFalse(requests.isEmpty(),
         "LDAPConnectionPool.processRequests.requests must not be empty.");

    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPSearchException(le);
    }

    final ArrayList<LDAPResult> results = new ArrayList<>(requests.size());
    boolean isDefunct = false;

    try
    {
requestLoop:
      for (final LDAPRequest request : requests)
      {
        try
        {
          final LDAPResult result = conn.processOperation(request);
          results.add(result);
          switch (result.getResultCode().intValue())
          {
            case ResultCode.SUCCESS_INT_VALUE:
            case ResultCode.COMPARE_FALSE_INT_VALUE:
            case ResultCode.COMPARE_TRUE_INT_VALUE:
            case ResultCode.NO_OPERATION_INT_VALUE:
              // These will be considered successful operations.
              break;

            default:
              // Anything else will be considered a failure.
              if (! ResultCode.isConnectionUsable(result.getResultCode()))
              {
                isDefunct = true;
              }

              if (! continueOnError)
              {
                break requestLoop;
              }
              break;
          }
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          results.add(new LDAPResult(request.getLastMessageID(),
                                     le.getResultCode(), le.getMessage(),
                                     le.getMatchedDN(), le.getReferralURLs(),
                                     le.getResponseControls()));

          if (! ResultCode.isConnectionUsable(le.getResultCode()))
          {
            isDefunct = true;
          }

          if (! continueOnError)
          {
            break;
          }
        }
      }
    }
    finally
    {
      if (isDefunct)
      {
        releaseDefunctConnection(conn);
      }
      else
      {
        releaseConnection(conn);
      }
    }

    return results;
  }



  /**
   * Processes multiple requests over a single connection from this pool using
   * asynchronous processing to cause the operations to be processed
   * concurrently.  The list of requests may contain only add, compare, delete,
   * modify, modify DN, and search operations (and any search operations to be
   * processed must be configured with an {@link AsyncSearchResultListener}.
   * This method will not return until all operations have completed, or until
   * the specified timeout period has elapsed.  The order of elements in the
   * list of the {@link AsyncRequestID} objects returned will correspond to the
   * order of elements in the list of requests.  The operation results may be
   * obtained from the returned {@code AsyncRequestID} objects using the
   * {@code java.util.concurrent.Future} API.
   *
   * @param  requests           The list of requests to be processed.  It must
   *                            not be {@code null} or empty, and it must
   *                            contain only add, compare, modify, modify DN,
   *                            and search requests.  Any search requests must
   *                            be configured with an
   *                            {@code AsyncSearchResultListener}.
   * @param  maxWaitTimeMillis  The maximum length of time in milliseconds to
   *                            wait for the operations to complete before
   *                            returning.  A value that is less than or equal
   *                            to zero indicates that the client should wait
   *                            indefinitely for the operations to complete.
   *
   * @return  The list of {@code AsyncRequestID} objects that may be used to
   *          retrieve the results for the operations.  The order of elements in
   *          this list will correspond to the order of the provided requests.
   *
   * @throws  LDAPException  If there is a problem with any of the requests, or
   *                         if connections in the pool are configured to use
   *                         synchronous mode and therefore cannot be used to
   *                         process asynchronous operations.
   */
  @NotNull()
  public final List<AsyncRequestID> processRequestsAsync(
                    @NotNull final List<LDAPRequest> requests,
                    final long maxWaitTimeMillis)
         throws LDAPException
  {
    // Make sure the set of requests is not null or empty.
    Validator.ensureNotNull(requests);
    Validator.ensureFalse(requests.isEmpty(),
         "LDAPConnectionPool.processRequests.requests must not be empty.");

    // Make sure that all the requests are acceptable.
    for (final LDAPRequest r : requests)
    {
      switch (r.getOperationType())
      {
        case ADD:
        case COMPARE:
        case DELETE:
        case MODIFY:
        case MODIFY_DN:
          // These operation types are always acceptable for asynchronous
          // processing.
          break;

        case SEARCH:
          // Search operations will only be acceptable if they have been
          // configured with an async search result listener.
          final SearchRequest searchRequest = (SearchRequest) r;
          if ((searchRequest.getSearchResultListener() == null) ||
              (! (searchRequest.getSearchResultListener() instanceof
                   AsyncSearchResultListener)))
          {
            throw new LDAPException(ResultCode.PARAM_ERROR,
                 ERR_POOL_PROCESS_REQUESTS_ASYNC_SEARCH_NOT_ASYNC.get(
                      String.valueOf(r)));
          }
          break;

        case ABANDON:
        case BIND:
        case EXTENDED:
        case UNBIND:
        default:
          // These operation types are never acceptable for asynchronous
          // processing.
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_POOL_PROCESS_REQUESTS_ASYNC_OP_NOT_ASYNC.get(
                    String.valueOf(r)));
      }
    }


    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPSearchException(le);
    }


    final ArrayList<AsyncRequestID> requestIDs =
         new ArrayList<>(requests.size());
    boolean isDefunct = false;

    try
    {
      // Make sure that the connection is not configured to use synchronous
      // mode, because asynchronous operations are not allowed in that mode.
      if (conn.synchronousMode())
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_POOL_PROCESS_REQUESTS_ASYNC_SYNCHRONOUS_MODE.get());
      }


      // Issue all of the requests.  If an exception is encountered while
      // issuing a request, then convert it into an AsyncRequestID with the
      // exception as the result.
      for (final LDAPRequest r : requests)
      {
        AsyncRequestID requestID = null;
        try
        {
          switch (r.getOperationType())
          {
            case ADD:
              requestID = conn.asyncAdd((AddRequest) r, null);
              break;
            case COMPARE:
              requestID = conn.asyncCompare((CompareRequest) r, null);
              break;
            case DELETE:
              requestID = conn.asyncDelete((DeleteRequest) r, null);
              break;
            case MODIFY:
              requestID = conn.asyncModify((ModifyRequest) r, null);
              break;
            case MODIFY_DN:
              requestID = conn.asyncModifyDN((ModifyDNRequest) r, null);
              break;
            case SEARCH:
              requestID = conn.asyncSearch((SearchRequest) r);
              break;
          }
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          requestID = new AsyncRequestID(r.getLastMessageID(), conn);
          requestID.setResult(le.toLDAPResult());
        }

        requestIDs.add(requestID);
      }


      // Wait for the operations to complete.  If any operation does not
      // complete before the specified timeout, then create a failure result for
      // it.  If any operation does not complete successfully, then attempt to
      // determine whether the failure may indicate that the connection is no
      // longer valid.
      final long startWaitingTime = System.currentTimeMillis();
      final long stopWaitingTime;
      if (maxWaitTimeMillis > 0)
      {
        stopWaitingTime = startWaitingTime + maxWaitTimeMillis;
      }
      else
      {
        stopWaitingTime = Long.MAX_VALUE;
      }

      for (final AsyncRequestID requestID : requestIDs)
      {
        LDAPResult result;
        final long waitTime = stopWaitingTime - System.currentTimeMillis();
        if (waitTime > 0)
        {
          try
          {
            result = requestID.get(waitTime, TimeUnit.MILLISECONDS);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            requestID.cancel(true);

            if (e instanceof TimeoutException)
            {
              result = new LDAPResult(requestID.getMessageID(),
                   ResultCode.TIMEOUT,
                   ERR_POOL_PROCESS_REQUESTS_ASYNC_RESULT_TIMEOUT.get(
                        (System.currentTimeMillis() - startWaitingTime)),
                   null, StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS);
            }
            else
            {
              result = new LDAPResult(requestID.getMessageID(),
                   ResultCode.LOCAL_ERROR,
                   ERR_POOL_PROCESS_REQUESTS_ASYNC_RESULT_EXCEPTION.get(
                        StaticUtils.getExceptionMessage(e)),
                   null, StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS);
            }
            requestID.setResult(result);
          }
        }
        else
        {
          requestID.cancel(true);
          result = new LDAPResult(requestID.getMessageID(),
               ResultCode.TIMEOUT,
               ERR_POOL_PROCESS_REQUESTS_ASYNC_RESULT_TIMEOUT.get(
                    (System.currentTimeMillis() - startWaitingTime)),
               null, StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS);
          requestID.setResult(result);
        }


        // See if we think that the connection may be defunct.
        if (! ResultCode.isConnectionUsable(result.getResultCode()))
        {
          isDefunct = true;
        }
      }

      return requestIDs;
    }
    finally
    {
      if (isDefunct)
      {
        releaseDefunctConnection(conn);
      }
      else
      {
        releaseConnection(conn);
      }
    }
  }



  /**
   * Examines the provided {@code Throwable} object to determine whether it
   * represents an {@code LDAPException} that indicates the associated
   * connection may no longer be valid.  If that is the case, and if such
   * operations should be retried, then no exception will be thrown.  Otherwise,
   * an appropriate {@code LDAPException} will be thrown.
   *
   * @param  t     The {@code Throwable} object that was caught.
   * @param  o     The type of operation for which to make the determination.
   * @param  conn  The connection to be released to the pool.
   *
   * @throws  LDAPException  To indicate that a problem occurred during LDAP
   *                         processing and the operation should not be retried.
   */
  private void throwLDAPExceptionIfShouldNotRetry(@NotNull final Throwable t,
                    @NotNull final OperationType o,
                    @NotNull final LDAPConnection conn)
          throws LDAPException
  {
    if ((t instanceof LDAPException) &&
        getOperationTypesToRetryDueToInvalidConnections().contains(o))
    {
      final LDAPException le = (LDAPException) t;
      final LDAPConnectionPoolHealthCheck healthCheck = getHealthCheck();

      try
      {
        healthCheck.ensureConnectionValidAfterException(conn, le);
      }
      catch (final Exception e)
      {
        // If we have gotten this exception, then it indicates that the
        // connection is no longer valid and the operation should be retried.
        Debug.debugException(e);
        return;
      }
    }

    throwLDAPException(t, conn);
  }



  /**
   * Examines the provided {@code Throwable} object to determine whether it
   * represents an {@code LDAPException} that indicates the associated
   * connection may no longer be valid.  If that is the case, and if such
   * operations should be retried, then no exception will be thrown.  Otherwise,
   * an appropriate {@code LDAPSearchException} will be thrown.
   *
   * @param  t     The {@code Throwable} object that was caught.
   * @param  conn  The connection to be released to the pool.
   *
   * @throws  LDAPSearchException  To indicate that a problem occurred during
   *                               LDAP processing and the operation should not
   *                               be retried.
   */
  private void throwLDAPSearchExceptionIfShouldNotRetry(
                    @NotNull final Throwable t,
                    @NotNull final LDAPConnection conn)
          throws LDAPSearchException
  {
    if ((t instanceof LDAPException) &&
        getOperationTypesToRetryDueToInvalidConnections().contains(
             OperationType.SEARCH))
    {
      final LDAPException le = (LDAPException) t;
      final LDAPConnectionPoolHealthCheck healthCheck = getHealthCheck();

      try
      {
        healthCheck.ensureConnectionValidAfterException(conn, le);
      }
      catch (final Exception e)
      {
        // If we have gotten this exception, then it indicates that the
        // connection is no longer valid and the operation should be retried.
        Debug.debugException(e);
        return;
      }
    }

    throwLDAPSearchException(t, conn);
  }



  /**
   * Handles the provided {@code Throwable} object by ensuring that the provided
   * connection is released to the pool and throwing an appropriate
   * {@code LDAPException} object.
   *
   * @param  t     The {@code Throwable} object that was caught.
   * @param  conn  The connection to be released to the pool.
   *
   * @throws  LDAPException  To indicate that a problem occurred during LDAP
   *                         processing.
   */
  void throwLDAPException(@NotNull final Throwable t,
                          @NotNull final LDAPConnection conn)
       throws LDAPException
  {
    Debug.debugException(t);
    if (t instanceof LDAPException)
    {
      final LDAPException le = (LDAPException) t;
      releaseConnectionAfterException(conn, le);
      throw le;
    }
    else
    {
      releaseDefunctConnection(conn);
      StaticUtils.rethrowIfError(t);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_POOL_OP_EXCEPTION.get(StaticUtils.getExceptionMessage(t)), t);
    }
  }



  /**
   * Handles the provided {@code Throwable} object by ensuring that the provided
   * connection is released to the pool and throwing an appropriate
   * {@code LDAPSearchException} object.
   *
   * @param  t     The {@code Throwable} object that was caught.
   * @param  conn  The connection to be released to the pool.
   *
   * @throws  LDAPSearchException  To indicate that a problem occurred during
   *                               LDAP search processing.
   */
  void throwLDAPSearchException(@NotNull final Throwable t,
                                @NotNull final LDAPConnection conn)
       throws LDAPSearchException
  {
    Debug.debugException(t);
    if (t instanceof LDAPException)
    {
      final LDAPSearchException lse;
      if (t instanceof LDAPSearchException)
      {
        lse = (LDAPSearchException) t;
      }
      else
      {
        lse = new LDAPSearchException((LDAPException) t);
      }

      releaseConnectionAfterException(conn, lse);
      throw lse;
    }
    else
    {
      releaseDefunctConnection(conn);
      StaticUtils.rethrowIfError(t);
      throw new LDAPSearchException(ResultCode.LOCAL_ERROR,
           ERR_POOL_OP_EXCEPTION.get(StaticUtils.getExceptionMessage(t)), t);
    }
  }



  /**
   * Retrieves a string representation of this connection pool.
   *
   * @return  A string representation of this connection pool.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this connection pool to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public abstract void toString(@NotNull StringBuilder buffer);
}
