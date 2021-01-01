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



import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.sdk.extensions.CancelExtendedRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.TopologyRegistryTrustManager;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.AggregateTrustManager;
import com.unboundid.util.ssl.JVMDefaultTrustManager;
import com.unboundid.util.ssl.PromptTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class serves as a proxy that provides access to selected package-private
 * methods in classes in the {@code com.unboundid.ldap.sdk} package so that they
 * may be called by code in other packages within the LDAP SDK.  Neither this
 * class nor the methods it contains may be used outside of the LDAP SDK.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class InternalSDKHelper
{
  /**
   * Prevent this class from being instantiated.
   */
  private InternalSDKHelper()
  {
    // No implementation is required.
  }



  /**
   * Retrieves the value (in milliseconds) of the SO_TIMEOUT socket option from
   * the socket associated with the provided connection.
   *
   * @param  connection  The connection for which to retrieve the SO_TIMEOUT
   *                     socket option value.  It must not be {@code null}.
   *
   * @return  The value (in milliseconds) of the SO_TIMEOUT socket option from
   *          the socket associated with the provided connection.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         get the SO_TIMEOUT value.
   */
  public static int getSoTimeout(@NotNull final LDAPConnection connection)
         throws LDAPException
  {
    try
    {
      return connection.getConnectionInternals(true).getSocket().getSoTimeout();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_INTERNAL_SDK_HELPER_CANNOT_GET_SO_TIMEOUT.get(
                String.valueOf(connection), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Sets the value (in milliseconds) of the SO_TIMEOUT socket option on the
   * socket associated with the provided connection.  It will take effect for
   * the next blocking operation that is performed on the socket.
   *
   * @param  connection  The connection for which the SO_TIMEOUT option will be
   *                     set.
   * @param  soTimeout   The SO_TIMEOUT value (in milliseconds) that should be
   *                     used for the connection.  It must be greater than or
   *                     equal to zero, with a timeout of zero indicating an
   *                     unlimited timeout.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         set the SO_TIMEOUT value.
   */
  @InternalUseOnly()
  public static void setSoTimeout(@NotNull final LDAPConnection connection,
                                  final int soTimeout)
         throws LDAPException
  {
    if (Debug.debugEnabled())
    {
      Debug.debug(Level.INFO, DebugType.CONNECT,
           "Setting the SO_TIMEOUT value for connection " + connection +
                " to " + soTimeout + "ms.");
    }

    try
    {
      if (connection != null)
      {
        final LDAPConnectionInternals internals =
             connection.getConnectionInternals(false);
        if (internals != null)
        {
          internals.getSocket().setSoTimeout(soTimeout);
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_INTERNAL_SDK_HELPER_CANNOT_SET_SO_TIMEOUT.get(
                String.valueOf(connection), soTimeout,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Converts the provided clear-text connection to one that encrypts all
   * communication using Transport Layer Security.  This method is intended for
   * use as a helper for processing in the course of the StartTLS extended
   * operation and should not be used for other purposes.
   *
   * @param  connection        The LDAP connection to be converted to use TLS.
   * @param  sslSocketFactory  The SSL socket factory to use to convert an
   *                           insecure connection into a secure connection.  It
   *                           must not be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while converting the provided
   *                         connection to use TLS.
   */
  @InternalUseOnly()
  public static void convertToTLS(@NotNull final LDAPConnection connection,
                          @NotNull final SSLSocketFactory sslSocketFactory)
         throws LDAPException
  {
    connection.convertToTLS(sslSocketFactory);
  }



  /**
   * Creates a new asynchronous request ID with the specified LDAP message ID.
   *
   * @param  targetMessageID  The message ID to use for the asynchronous request
   *                          ID.
   * @param  connection       The connection on which the associated request has
   *                          been sent.
   *
   * @return  The new asynchronous request ID.
   */
  @InternalUseOnly()
  @NotNull()
  public static AsyncRequestID createAsyncRequestID(final int targetMessageID,
                                    @NotNull final LDAPConnection connection)
  {
    return new AsyncRequestID(targetMessageID, connection);
  }



  /**
   * Sends an LDAP cancel extended request to the server over the provided
   * connection without waiting for the response.  This is intended for use when
   * it is necessary to send a cancel request over a connection operating in
   * synchronous mode.
   *
   * @param  connection       The connection over which to send the cancel
   *                          request.
   * @param  targetMessageID  The message ID of the request to cancel.
   * @param  controls         The set of controls to include in the request.
   *
   * @throws  LDAPException  If a problem occurs while sending the cancel
   *                         request.
   */
  @InternalUseOnly()
  public static void cancel(@NotNull final LDAPConnection connection,
                            final int targetMessageID,
                            @Nullable final Control... controls)
         throws LDAPException
  {
    final int messageID = connection.nextMessageID();
    final CancelExtendedRequest cancelRequest =
         new CancelExtendedRequest(targetMessageID);
    Debug.debugLDAPRequest(Level.INFO, cancelRequest, messageID, connection);

    final LDAPConnectionLogger logger =
         connection.getConnectionOptions().getConnectionLogger();
    if (logger != null)
    {
      logger.logExtendedRequest(connection, messageID, cancelRequest);
    }

    connection.sendMessage(
         new LDAPMessage(messageID, new ExtendedRequest(cancelRequest),
              controls),
         connection.getConnectionOptions().
              getExtendedOperationResponseTimeoutMillis(
                   CancelExtendedRequest.CANCEL_REQUEST_OID));
  }



  /**
   * Creates a new LDAP result object with the provided message ID and with the
   * protocol op and controls read from the given ASN.1 stream reader.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this LDAP result.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded LDAP result object.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @InternalUseOnly()
  @NotNull()
  public static LDAPResult readLDAPResultFrom(final int messageID,
                     @NotNull final ASN1StreamReaderSequence messageSequence,
                     @NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    return LDAPResult.readLDAPResultFrom(messageID, messageSequence, reader);
  }



  /**
   * Creates a new bind result object with the provided message ID and with the
   * protocol op and controls read from the given ASN.1 stream reader.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this bind result.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded bind result object.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @InternalUseOnly()
  @NotNull()
  public static BindResult readBindResultFrom(final int messageID,
                     @NotNull final ASN1StreamReaderSequence messageSequence,
                     @NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    return BindResult.readBindResultFrom(messageID, messageSequence, reader);
  }



  /**
   * Creates a new compare result object with the provided message ID and with
   * the protocol op and controls read from the given ASN.1 stream reader.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this compare result.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded compare result object.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @InternalUseOnly()
  @NotNull()
  public static CompareResult readCompareResultFrom(final int messageID,
                     @NotNull final ASN1StreamReaderSequence messageSequence,
                     @NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    return CompareResult.readCompareResultFrom(messageID, messageSequence,
                                               reader);
  }



  /**
   * Creates a new extended result object with the provided message ID and with
   * the protocol op and controls read from the given ASN.1 stream reader.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this extended result.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded extended result object.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @InternalUseOnly()
  @NotNull()
  public static ExtendedResult readExtendedResultFrom(final int messageID,
                     @NotNull final ASN1StreamReaderSequence messageSequence,
                     @NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    return ExtendedResult.readExtendedResultFrom(messageID, messageSequence,
                                                 reader);
  }



  /**
   * Creates a new search result entry object with the protocol op and controls
   * read from the given ASN.1 stream reader.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this search result entry.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   * @param  schema           The schema to use to select the appropriate
   *                          matching rule to use for each attribute.  It may
   *                          be {@code null} if the default matching rule
   *                          should always be used.
   *
   * @return  The decoded search result entry object.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @InternalUseOnly()
  @NotNull()
  public static SearchResultEntry readSearchResultEntryFrom(final int messageID,
                     @NotNull final ASN1StreamReaderSequence messageSequence,
                     @NotNull final ASN1StreamReader reader,
                     @Nullable final Schema schema)
         throws LDAPException
  {
    return SearchResultEntry.readSearchEntryFrom(messageID, messageSequence,
                                                 reader, schema);
  }



  /**
   * Creates a new search result reference object with the protocol op and
   * controls read from the given ASN.1 stream reader.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this search result entry.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded search result reference object.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @InternalUseOnly()
  @NotNull()
  public static SearchResultReference readSearchResultReferenceFrom(
                     final int messageID,
                     @NotNull final ASN1StreamReaderSequence messageSequence,
                     @NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    return SearchResultReference.readSearchReferenceFrom(messageID,
                messageSequence, reader);
  }



  /**
   * Creates a new search result object with the provided message ID and with
   * the protocol op and controls read from the given ASN.1 stream reader.  It
   * will be necessary for the caller to ensure that the entry and reference
   * details are updated.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this search result.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded search result object.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @InternalUseOnly()
  @NotNull()
  public static SearchResult readSearchResultFrom(final int messageID,
                     @NotNull final ASN1StreamReaderSequence messageSequence,
                     @NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    return SearchResult.readSearchResultFrom(messageID, messageSequence,
                                             reader);
  }



  /**
   * Creates a new intermediate response object with the provided message ID and
   * with the protocol op and controls read from the given ASN.1 stream reader.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this intermediate response.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded intermediate response object.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @InternalUseOnly()
  @NotNull()
  public static IntermediateResponse readIntermediateResponseFrom(
                     final int messageID,
                     @NotNull final ASN1StreamReaderSequence messageSequence,
                     @NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    return IntermediateResponse.readFrom(messageID, messageSequence, reader);
  }



  /**
   * Indicates whether automatic referral following is enabled for the provided
   * request.
   *
   * @param  request  The request for which to make the determination.
   *
   * @return  {@code Boolean.TRUE} if automatic referral following is enabled
   *          for this request, {@code Boolean.FALSE} if not, or {@code null} if
   *          a per-request behavior is not specified.
   */
  @InternalUseOnly()
  @Nullable()
  public static Boolean followReferralsInternal(
                             @NotNull final LDAPRequest request)
  {
    return request.followReferralsInternal();
  }



  /**
   * Retrieves the referral connector that has been set for the provided
   * request.
   *
   * @param  request  The request for which to obtain the referral connector.
   *
   * @return  The referral connector that has been set for the provided request,
   *          or {@code null} if no referral connector has been set for the
   *          request and the connection's default referral connector will be
   *          used if necessary.
   */
  @InternalUseOnly()
  @Nullable()
  public static ReferralConnector getReferralConnectorInternal(
                                       @NotNull final LDAPRequest request)
  {
    return request.getReferralConnectorInternal();
  }



  /**
   * Retrieves the message ID that should be used for the next request sent
   * over the provided connection.
   *
   * @param  connection  The LDAP connection for which to obtain the next
   *                     request message ID.
   *
   * @return  The message ID that should be used for the next request sent over
   *          the provided connection, or -1 if the connection is not
   *          established.
   */
  @InternalUseOnly()
  public static int nextMessageID(@NotNull final LDAPConnection connection)
  {
    return connection.nextMessageID();
  }



  /**
   * Retrieves the last successful bind request processed on the provided
   * connection.
   *
   * @param  connection  The LDAP connection for which to obtain the last
   *                     successful bind request.
   *
   * @return  The last successful bind request processed on the provided
   *          connection.  It may be {@code null} if no bind has been performed
   *          on the connection, or if the last bind attempt was not successful.
   */
  @InternalUseOnly()
  @Nullable()
  public static BindRequest getLastBindRequest(
                                 @NotNull final LDAPConnection connection)
  {
    return connection.getLastBindRequest();
  }



  /**
   * Retrieves the schema that will be used for the provided entry, if any.
   *
   * @param  entry  The entry for which to retrieve the schema.  It must not be
   *                {@code null}.
   *
   * @return  The schema that will be used for the provided entry, or
   *          {@code null} if no schema was provided for the entry.
   */
  @InternalUseOnly()
  @Nullable()
  public static Schema getEntrySchema(@NotNull final Entry entry)
  {
    return entry.getSchema();
  }



  /**
   * Retrieves the path to the instance root directory for the Ping Identity
   * Directory Server (or related Ping Identity server product) with which this
   * instance of the LDAP SDK is associated.
   *
   * @return  The path to the associated Ping Identity server instance root, or
   *          {@code null} if the LDAP SDK is not running with knowledge of an
   *          associated Ping Identity server instance.
   */
  @InternalUseOnly()
  @Nullable()
  public static File getPingIdentityServerRoot()
  {
    final String propertyValue = StaticUtils.getSystemProperty(
         "com.unboundid.directory.server.ServerRoot");
    if (propertyValue != null)
    {
      try
      {
        final File f = new File(propertyValue);
        if (f.exists() && f.isDirectory())
        {
          return f;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    final String environmentVariableValue =
         StaticUtils.getEnvironmentVariable("INSTANCE_ROOT");
    if (environmentVariableValue != null)
    {
      try
      {
        final File f = new File(environmentVariableValue);
        if (f.exists() && f.isDirectory())
        {
          return f;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return null;
  }



  /**
   * Retrieves an aggregate trust manager that can be used to interactively
   * prompt the user about whether to trust a presented certificate chain as a
   * last resort, but will try other alternatives first, including the
   * JVM-default trust store and, if the tool is run with access to a Ping
   * Identity Directory Server instance, then it will also try to use the
   * server's default trust store and information in the topology registry.
   *
   * @param  expectedAddresses  An optional collection of the addresses that the
   *                            client is expected to use to connect to one of
   *                            the target servers.  This may be {@code null} or
   *                            empty if no expected addresses are available, if
   *                            this trust manager is only expected to be used
   *                            to validate client certificates, or if no server
   *                            address validation should be performed.  If a
   *                            non-empty collection is provided, then the trust
   *                            manager may issue a warning if the certificate
   *                            does not contain any of these addresses.
   *
   * @return  An aggregate trust manager that can be used to interactively
   *          prompt the user about whether to trust a presented certificate
   *          chain as a last resort, but will try other alternatives first.
   */
  @InternalUseOnly()
  @NotNull()
  public static AggregateTrustManager getPreferredPromptTrustManagerChain(
                     @Nullable final Collection<String> expectedAddresses)
  {
    final List<X509TrustManager> trustManagers = new ArrayList<>(4);
    trustManagers.add(JVMDefaultTrustManager.getInstance());

    final File pingIdentityServerRoot =
         InternalSDKHelper.getPingIdentityServerRoot();
    if (pingIdentityServerRoot != null)
    {
      final File serverTrustStore = StaticUtils.constructPath(
           pingIdentityServerRoot, "config", "truststore");
      if (serverTrustStore.exists())
      {
        trustManagers.add(new TrustStoreTrustManager(serverTrustStore));
      }

      final File serverConfigFile = StaticUtils.constructPath(
           pingIdentityServerRoot, "config", "config.ldif");
      if (serverConfigFile.exists())
      {
        trustManagers.add(new TopologyRegistryTrustManager(serverConfigFile,
             TimeUnit.MINUTES.toMillis(5L)));
      }
    }

    trustManagers.add(new PromptTrustManager(null, true, expectedAddresses,
         null, null));

    return new AggregateTrustManager(false, trustManagers);
  }
}
