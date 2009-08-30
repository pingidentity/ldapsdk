/*
 * Copyright 2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009 UnboundID Corp.
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



import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides the base class for LDAP connection pool implementations
 * provided by the LDAP SDK for Java.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class AbstractConnectionPool
       implements LDAPInterface
{
  /**
   * Closes this connection pool.  All connections currently held in the pool
   * that are not in use will be closed, and any outstanding connections will be
   * automatically closed when they are released back to the pool.
   */
  public abstract void close();



  /**
   * Retrieves an LDAP connection from the pool.
   *
   * @return  The LDAP connection taken from the pool.
   *
   * @throws  LDAPException  If no connection is available, or a problem occurs
   *                         while creating a new connection to return.
   */
  public abstract LDAPConnection getConnection()
         throws LDAPException;



  /**
   * Releases the provided connection back to this pool.
   *
   * @param  connection  The connection to be released back to the pool.
   */
  public abstract void releaseConnection(final LDAPConnection connection);



  /**
   * Indicates that the provided connection is no longer in use, but is also no
   * longer fit for use.  The provided connection will be terminated and a new
   * connection will be created and added to the pool in its place.
   *
   * @param  connection  The defunct connection being released.
   */
  public abstract void releaseDefunctConnection(
                            final LDAPConnection connection);



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
  public void releaseConnectionAfterException(final LDAPConnection connection,
                                              final LDAPException exception)
  {
    final LDAPConnectionPoolHealthCheck healthCheck = getHealthCheck();

    try
    {
      healthCheck.ensureConnectionValidAfterException(connection, exception);
      releaseConnection(connection);
    }
    catch (LDAPException le)
    {
      debugException(le);
      releaseDefunctConnection(connection);
    }
  }



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
  public abstract LDAPConnectionPoolStatistics getConnectionPoolStatistics();



  /**
   * Retrieves the user-friendly name that has been assigned to this connection
   * pool.
   *
   * @return  The user-friendly name that has been assigned to this connection
   *          pool, or {@code null} if none has been assigned.
   */
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
  public abstract void setConnectionPoolName(final String connectionPoolName);



  /**
   * Retrieves the health check implementation for this connection pool.
   *
   * @return  The health check implementation for this connection pool.
   */
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
  public abstract void setHealthCheckIntervalMillis(
                            final long healthCheckInterval);



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
  public RootDSE getRootDSE()
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final RootDSE rootDSE = conn.getRootDSE();
      releaseConnection(conn);
      return rootDSE;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public Schema getSchema()
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final Schema schema = conn.getSchema();
      releaseConnection(conn);
      return schema;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

      // This return statement should never be reached.
      return null;
    }
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
  public Schema getSchema(final String entryDN)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final Schema schema = conn.getSchema(entryDN);
      releaseConnection(conn);
      return schema;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public SearchResultEntry getEntry(final String dn)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final SearchResultEntry entry = conn.getEntry(dn);
      releaseConnection(conn);
      return entry;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

      // This return statement should never be reached.
      return null;
    }
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
  public SearchResultEntry getEntry(final String dn, final String... attributes)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final SearchResultEntry entry = conn.getEntry(dn, attributes);
      releaseConnection(conn);
      return entry;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public LDAPResult add(final String dn, final Attribute... attributes)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.add(dn, attributes);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public LDAPResult add(final String dn, final Collection<Attribute> attributes)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.add(dn, attributes);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

      // This return statement should never be reached.
      return null;
    }
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
  public LDAPResult add(final Entry entry)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.add(entry);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

      // This return statement should never be reached.
      return null;
    }
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
  public LDAPResult add(final String... ldifLines)
         throws LDIFException, LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.add(ldifLines);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPOrLDIFException(t, conn);

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
  public LDAPResult add(final AddRequest addRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.add(addRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public LDAPResult add(final ReadOnlyAddRequest addRequest)
         throws LDAPException
  {
    return add((AddRequest) addRequest);
  }



  /**
   * Processes a simple bind request with the provided DN and password using a
   * connection from this connection pool.  Note that this will impact the state
   * of the connection in the pool, and therefore this method should only be
   * used if this connection pool is used exclusively for processing bind
   * operations, or if the retain identity request control is included in the
   * bind request to ensure that the authentication state is not impacted.
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
  public BindResult bind(final String bindDN, final String password)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final BindResult result = conn.bind(bindDN, password);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes the provided bind request using a connection from this connection
   * pool.  Note that this will impact the state of the connection in the pool,
   * and therefore this method should only be used if this connection pool is
   * used exclusively for processing bind operations, or if the retain identity
   * request control is included in the bind request to ensure that the
   * authentication state is not impacted.
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
  public BindResult bind(final BindRequest bindRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final BindResult result = conn.bind(bindRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public CompareResult compare(final String dn, final String attributeName,
                               final String assertionValue)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final CompareResult result =
           conn.compare(dn, attributeName, assertionValue);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public CompareResult compare(final CompareRequest compareRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final CompareResult result = conn.compare(compareRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public CompareResult compare(final ReadOnlyCompareRequest compareRequest)
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
  public LDAPResult delete(final String dn)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.delete(dn);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public LDAPResult delete(final DeleteRequest deleteRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.delete(deleteRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public LDAPResult delete(final ReadOnlyDeleteRequest deleteRequest)
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
  public ExtendedResult processExtendedOperation(final String requestOID)
         throws LDAPException
  {
    if (requestOID.equals(StartTLSExtendedRequest.STARTTLS_REQUEST_OID))
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
                              ERR_POOL_STARTTLS_NOT_ALLOWED.get());
    }

    final LDAPConnection conn = getConnection();

    try
    {
      final ExtendedResult result = conn.processExtendedOperation(requestOID);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

      // This return statement should never be reached.
      return null;
    }
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
  public ExtendedResult processExtendedOperation(final String requestOID,
                             final ASN1OctetString requestValue)
         throws LDAPException
  {
    if (requestOID.equals(StartTLSExtendedRequest.STARTTLS_REQUEST_OID))
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
                              ERR_POOL_STARTTLS_NOT_ALLOWED.get());
    }

    final LDAPConnection conn = getConnection();

    try
    {
      final ExtendedResult result =
           conn.processExtendedOperation(requestOID, requestValue);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

      // This return statement should never be reached.
      return null;
    }
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
  public ExtendedResult processExtendedOperation(
                               final ExtendedRequest extendedRequest)
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
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public LDAPResult modify(final String dn, final Modification mod)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.modify(dn, mod);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

      // This return statement should never be reached.
      return null;
    }
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
  public LDAPResult modify(final String dn, final Modification... mods)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.modify(dn, mods);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

      // This return statement should never be reached.
      return null;
    }
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
  public LDAPResult modify(final String dn, final List<Modification> mods)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.modify(dn, mods);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

      // This return statement should never be reached.
      return null;
    }
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
  public LDAPResult modify(final String... ldifModificationLines)
         throws LDIFException, LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.modify(ldifModificationLines);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPOrLDIFException(t, conn);

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
  public LDAPResult modify(final ModifyRequest modifyRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.modify(modifyRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public LDAPResult modify(final ReadOnlyModifyRequest modifyRequest)
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
  public LDAPResult modifyDN(final String dn, final String newRDN,
                             final boolean deleteOldRDN)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.modifyDN(dn, newRDN, deleteOldRDN);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

      // This return statement should never be reached.
      return null;
    }
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
  public LDAPResult modifyDN(final String dn, final String newRDN,
                             final boolean deleteOldRDN,
                             final String newSuperiorDN)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result =
           conn.modifyDN(dn, newRDN, deleteOldRDN, newSuperiorDN);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public LDAPResult modifyDN(final ModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    final LDAPConnection conn = getConnection();

    try
    {
      final LDAPResult result = conn.modifyDN(modifyDNRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPException(t, conn);

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
  public LDAPResult modifyDN(final ReadOnlyModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return modifyDN((ModifyDNRequest) modifyDNRequest);
  }



  /**
   * Processes a search operation with the provided information using a
   * connection from this connection pool.  The search result entries and
   * references will be collected internally and included in the
   * {@code SearchResult} object that is returned.
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
   *                               request, or reading the response.
   */
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final String filter, final String... attributes)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResult result =
           conn.search(baseDN, scope, filter, attributes);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPSearchException(t, conn);

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes a search operation with the provided information using a
   * connection from this connection pool.  The search result entries and
   * references will be collected internally and included in the
   * {@code SearchResult} object that is returned.
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
   *                               the request or reading the response.
   */
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final Filter filter, final String... attributes)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResult result =
           conn.search(baseDN, scope, filter, attributes);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPSearchException(t, conn);

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes a search operation with the provided information using a
   * connection from this connection pool.
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
   *                               request, or reading the response.
   */
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final String filter, final String... attributes)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResult result =
           conn.search(searchResultListener, baseDN, scope, filter, attributes);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPSearchException(t, conn);

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes a search operation with the provided information using a
   * connection from this connection pool.
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
   *                               the request or reading the response.
   */
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final Filter filter, final String... attributes)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResult result =
           conn.search(searchResultListener, baseDN, scope, filter, attributes);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPSearchException(t, conn);

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes a search operation with the provided information using a
   * connection from this connection pool.  The search result entries and
   * references will be collected internally and included in the
   * {@code SearchResult} object that is returned.
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
   *                               request, or reading the response.
   */
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final String filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResult result = conn.search(baseDN, scope, derefPolicy,
           sizeLimit, timeLimit, typesOnly, filter, attributes);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPSearchException(t, conn);

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes a search operation with the provided information using a
   * connection from this connection pool.  The search result entries and
   * references will be collected internally and included in the
   * {@code SearchResult} object that is returned.
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
   *                               the request or reading the response.
   */
  public SearchResult search(final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final Filter filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResult result = conn.search(baseDN, scope, derefPolicy,
           sizeLimit, timeLimit, typesOnly, filter, attributes);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPSearchException(t, conn);

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes a search operation with the provided information using a
   * connection from this connection pool.
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
   *                               request, or reading the response.
   */
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final String filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResult result = conn.search(searchResultListener, baseDN,
           scope, derefPolicy, sizeLimit, timeLimit, typesOnly, filter,
           attributes);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPSearchException(t, conn);

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes a search operation with the provided information using a
   * connection from this connection pool.
   *
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
   *                               the request or reading the response.
   */
  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final Filter filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResult result = conn.search(searchResultListener, baseDN,
           scope, derefPolicy, sizeLimit, timeLimit, typesOnly, filter,
           attributes);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPSearchException(t, conn);

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes the provided search request using a connection from this
   * connection pool.
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
   *                               the request or reading the response.
   */
  public SearchResult search(final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    try
    {
      final SearchResult result = conn.search(searchRequest);
      releaseConnection(conn);
      return result;
    }
    catch (Throwable t)
    {
      throwLDAPSearchException(t, conn);

      // This return statement should never be reached.
      return null;
    }
  }



  /**
   * Processes the provided search request using a connection from this
   * connection pool.
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
   *                               the request or reading the response.
   */
  public SearchResult search(final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return search((SearchRequest) searchRequest);
  }



  /**
   * Processes multiple requests in the order they are provided over a single
   * connection from this pool.
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
  public List<LDAPResult> processRequests(final List<LDAPRequest> requests,
                                          final boolean continueOnError)
         throws LDAPException
  {
    ensureNotNull(requests);
    ensureFalse(requests.isEmpty(),
         "LDAPConnectionPool.processRequests.requests must not be empty.");

    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    final ArrayList<LDAPResult> results =
         new ArrayList<LDAPResult>(requests.size());
    boolean isDefunct = false;

    try
    {
requestLoop:
      for (final LDAPRequest request : requests)
      {
        try
        {
          final LDAPResult result = request.process(conn, 1);
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
        catch (LDAPException le)
        {
          debugException(le);
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
  void throwLDAPException(final Throwable t, final LDAPConnection conn)
       throws LDAPException
  {
    debugException(t);
    if (t instanceof LDAPException)
    {
      final LDAPException le = (LDAPException) t;
      releaseConnectionAfterException(conn, le);
      throw le;
    }
    else
    {
      releaseDefunctConnection(conn);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_POOL_OP_EXCEPTION.get(getExceptionMessage(t)), t);
    }
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
   *
   * @throws  LDIFException  To indicate that a problem occurred during LDIF
   *                         processing.
   */
  void throwLDAPOrLDIFException(final Throwable t, final LDAPConnection conn)
       throws LDAPException, LDIFException
  {
    debugException(t);
    if (t instanceof LDAPException)
    {
      final LDAPException le = (LDAPException) t;
      releaseConnectionAfterException(conn, le);
      throw le;
    }
    else if (t instanceof LDIFException)
    {
      releaseConnection(conn);
      throw (LDIFException) t;
    }
    else
    {
      releaseDefunctConnection(conn);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_POOL_OP_EXCEPTION.get(getExceptionMessage(t)), t);
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
  void throwLDAPSearchException(final Throwable t, final LDAPConnection conn)
       throws LDAPSearchException
  {
    debugException(t);
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
      throw new LDAPSearchException(ResultCode.LOCAL_ERROR,
           ERR_POOL_OP_EXCEPTION.get(getExceptionMessage(t)), t);
    }
  }



  /**
   * Retrieves a string representation of this connection pool.
   *
   * @return  A string representation of this connection pool.
   */
  @Override()
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
  public abstract void toString(final StringBuilder buffer);
}
