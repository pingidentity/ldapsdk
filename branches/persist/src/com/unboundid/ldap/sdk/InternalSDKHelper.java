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



import javax.net.ssl.SSLContext;

import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.sdk.extensions.CancelExtendedRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



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
   * Converts the provided clear-text connection to one that encrypts all
   * communication using Transport Layer Security.  This method is intended for
   * use as a helper for processing in the course of the StartTLS extended
   * operation and should not be used for other purposes.
   *
   * @param  connection  The LDAP connection to be converted to use TLS.
   * @param  sslContext  The SSL context to use when performing the negotiation.
   *                     It must not be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while converting the provided
   *                         connection to use TLS.
   */
  @InternalUseOnly()
  public static void convertToTLS(final LDAPConnection connection,
                                  final SSLContext sslContext)
         throws LDAPException
  {
    connection.convertToTLS(sslContext);
  }



  /**
   * Creates a new asynchronous request ID with the specified LDAP message ID.
   *
   * @param  targetMessageID  The message ID to use for the asynchronous request
   *                          ID.
   *
   * @return  The new asynchronous request ID.
   */
  @InternalUseOnly()
  public static AsyncRequestID createAsyncRequestID(final int targetMessageID)
  {
    return new AsyncRequestID(targetMessageID);
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
  public static void cancel(final LDAPConnection connection,
                            final int targetMessageID,
                            final Control... controls)
         throws LDAPException
  {
    final CancelExtendedRequest cancelRequest =
         new CancelExtendedRequest(targetMessageID);
    connection.sendMessage(new LDAPMessage(connection.nextMessageID(),
         new ExtendedRequest(cancelRequest), controls));
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
  public static LDAPResult readLDAPResultFrom(final int messageID,
                                final ASN1StreamReaderSequence messageSequence,
                                final ASN1StreamReader reader)
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
  public static BindResult readBindResultFrom(final int messageID,
                                final ASN1StreamReaderSequence messageSequence,
                                final ASN1StreamReader reader)
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
  public static CompareResult readCompareResultFrom(final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader)
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
  public static ExtendedResult readExtendedResultFrom(final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader)
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
  public static SearchResultEntry readSearchResultEntryFrom(final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader, final Schema schema)
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
  public static SearchResultReference readSearchResultReferenceFrom(
                     final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader)
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
  public static SearchResult readSearchResultFrom(final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader)
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
  public static IntermediateResponse readIntermediateResponseFrom(
                     final int messageID,
                     final ASN1StreamReaderSequence messageSequence,
                     final ASN1StreamReader reader)
         throws LDAPException
  {
    return IntermediateResponse.readFrom(messageID, messageSequence, reader);
  }
}
