/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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



import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.AbandonRequestProtocolOp;
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.AddResponseProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.BindResponseProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareResponseProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteResponseProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.IntermediateResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNResponseProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.protocol.SearchResultReferenceProtocolOp;
import com.unboundid.ldap.protocol.UnbindRequestProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a request handler that may be used to write detailed
 * information about the contents of all requests and responses that pass
 * through it.  It will be also be associated with another request handler that
 * will actually be used to handle the request.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPDebuggerRequestHandler
       extends LDAPListenerRequestHandler
       implements IntermediateResponseTransformer, SearchEntryTransformer,
                  SearchReferenceTransformer
{
  /**
   * The thread-local buffers that will be used to hold the log messages as they
   * are being generated.
   */
  @NotNull private static final ThreadLocal<StringBuilder> BUFFERS =
       new ThreadLocal<>();



  // The log handler that will be used to log the messages.
  @NotNull private final Handler logHandler;

  // The request handler that actually will be used to process any requests
  // received.
  @NotNull private final LDAPListenerRequestHandler requestHandler;

  // The header string that will be used before each message.
  @Nullable private final String headerString;



  /**
   * Creates a new LDAP debugger request handler that will write detailed
   * information about the contents of all requests and responses that pass
   * through it using the provided log handler, and will process client requests
   * using the provided request handler.
   *
   * @param  logHandler      The log handler that will be used to write detailed
   *                         information about requests and responses.  Note
   *                         that all messages will be logged at the INFO level.
   *                         It must not be {@code null}.  Note that the log
   *                         handler will not be automatically closed when the
   *                         associated listener is shut down.
   * @param  requestHandler  The request handler that will actually be used to
   *                         process any requests received.  It must not be
   *                         {@code null}.
   */
  public LDAPDebuggerRequestHandler(@NotNull final Handler logHandler,
              @NotNull final LDAPListenerRequestHandler requestHandler)
  {
    Validator.ensureNotNull(logHandler, requestHandler);

    this.logHandler     = logHandler;
    this.requestHandler = requestHandler;

    headerString = null;
  }



  /**
   * Creates a new LDAP debugger request handler that will write detailed
   * information about the contents of all requests and responses that pass
   * through it using the provided log handler, and will process client requests
   * using the provided request handler.
   *
   * @param  logHandler      The log handler that will be used to write detailed
   *                         information about requests and responses.  Note
   *                         that all messages will be logged at the INFO level.
   *                         It must not be {@code null}.
   * @param  requestHandler  The request handler that will actually be used to
   *                         process any requests received.  It must not be
   *                         {@code null}.
   * @param  headerString    The string that should be given as the first line
   *                         of every log message.
   */
  private LDAPDebuggerRequestHandler(@NotNull final Handler logHandler,
               @NotNull final LDAPListenerRequestHandler requestHandler,
               @NotNull final String headerString)
  {
    Validator.ensureNotNull(logHandler, requestHandler);

    this.logHandler     = logHandler;
    this.requestHandler = requestHandler;
    this.headerString    = headerString;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPDebuggerRequestHandler newInstance(
              @NotNull final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    final StringBuilder b = getBuffer();
    final Socket s = connection.getSocket();
    b.append("conn=");
    b.append(connection.getConnectionID());
    b.append(" from=\"");
    b.append(s.getInetAddress().getHostAddress());
    b.append(':');
    b.append(s.getPort());
    b.append("\" to=\"");
    b.append(s.getLocalAddress().getHostAddress());
    b.append(':');
    b.append(s.getLocalPort());
    b.append('"');
    b.append(StaticUtils.EOL);

    final String header = b.toString();

    final LDAPDebuggerRequestHandler h = new LDAPDebuggerRequestHandler(
         logHandler, requestHandler.newInstance(connection), header);

    connection.addIntermediateResponseTransformer(h);
    connection.addSearchEntryTransformer(h);
    connection.addSearchReferenceTransformer(h);

    logHandler.publish(new LogRecord(Level.INFO, "CONNECT " + header));
    logHandler.flush();

    return h;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void closeInstance()
  {
    final StringBuilder b = getBuffer();
    b.append("DISCONNECT ");
    b.append(headerString);

    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    requestHandler.closeInstance();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processAbandonRequest(final int messageID,
                   @NotNull final AbandonRequestProtocolOp request,
                   @NotNull final List<Control> controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Abandon Request Protocol Op:").append(StaticUtils.EOL);
    b.append("          ID to Abandon:  ").append(request.getIDToAbandon()).
         append(StaticUtils.EOL);

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    requestHandler.processAbandonRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processAddRequest(final int messageID,
                          @NotNull final AddRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Add Request Protocol Op:").append(StaticUtils.EOL);

    final Entry e = new Entry(request.getDN(), request.getAttributes());
    final String[] ldifLines = e.toLDIF(80);
    for (final String line : ldifLines)
    {
      b.append("          ").append(line).append(StaticUtils.EOL);
    }

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final LDAPMessage responseMessage = requestHandler.processAddRequest(
         messageID, request, controls);

    b.setLength(0);
    appendHeader(b, responseMessage.getMessageID());
    b.append("     Add Response Protocol Op:").append(StaticUtils.EOL);

    final AddResponseProtocolOp protocolOp =
         responseMessage.getAddResponseProtocolOp();
    appendResponse(b, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs());

    appendControls(b, responseMessage.getControls());
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processBindRequest(final int messageID,
                          @NotNull final BindRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Bind Request Protocol Op:").append(StaticUtils.EOL);
    b.append("          LDAP Version:  ").append(request.getVersion()).
         append(StaticUtils.EOL);
    b.append("          Bind DN:  ").append(request.getBindDN()).
         append(StaticUtils.EOL);

    switch (request.getCredentialsType())
    {
      case BindRequestProtocolOp.CRED_TYPE_SIMPLE:
        b.append("          Credentials Type:  SIMPLE").append(StaticUtils.EOL);
        b.append("               Password:  ").
             append(request.getSimplePassword()).append(StaticUtils.EOL);
        break;

      case BindRequestProtocolOp.CRED_TYPE_SASL:
        b.append("          Credentials Type:  SASL").append(StaticUtils.EOL);
        b.append("               Mechanism:  ").
             append(request.getSASLMechanism()).append(StaticUtils.EOL);

        final ASN1OctetString saslCredentials = request.getSASLCredentials();
        if (saslCredentials != null)
        {
          b.append("               Encoded Credentials:");
          b.append(StaticUtils.EOL);
          StaticUtils.toHexPlusASCII(saslCredentials.getValue(), 20, b);
        }
        break;
    }

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final LDAPMessage responseMessage = requestHandler.processBindRequest(
         messageID, request, controls);

    b.setLength(0);
    appendHeader(b, responseMessage.getMessageID());
    b.append("     Bind Response Protocol Op:").append(StaticUtils.EOL);

    final BindResponseProtocolOp protocolOp =
         responseMessage.getBindResponseProtocolOp();
    appendResponse(b, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs());

    final ASN1OctetString serverSASLCredentials =
         protocolOp.getServerSASLCredentials();
    if (serverSASLCredentials != null)
    {
      b.append("               Encoded Server SASL Credentials:");
      b.append(StaticUtils.EOL);
      StaticUtils.toHexPlusASCII(serverSASLCredentials.getValue(), 20, b);
    }

    appendControls(b, responseMessage.getControls());
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processCompareRequest(final int messageID,
                          @NotNull final CompareRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Compare Request Protocol Op:").append(StaticUtils.EOL);
    b.append("          DN:  ").append(request.getDN()).append(StaticUtils.EOL);
    b.append("          Attribute Type:  ").append(request.getAttributeName()).
         append(StaticUtils.EOL);
    b.append("          Assertion Value:  ").
         append(request.getAssertionValue().stringValue()).
         append(StaticUtils.EOL);

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final LDAPMessage responseMessage = requestHandler.processCompareRequest(
         messageID, request, controls);

    b.setLength(0);
    appendHeader(b, responseMessage.getMessageID());
    b.append("     Compare Response Protocol Op:").append(StaticUtils.EOL);

    final CompareResponseProtocolOp protocolOp =
         responseMessage.getCompareResponseProtocolOp();
    appendResponse(b, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs());

    appendControls(b, responseMessage.getControls());
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processDeleteRequest(final int messageID,
                          @NotNull final DeleteRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Delete Request Protocol Op:").append(StaticUtils.EOL);
    b.append("          DN:  ").append(request.getDN()).append(StaticUtils.EOL);

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final LDAPMessage responseMessage = requestHandler.processDeleteRequest(
         messageID, request, controls);

    b.setLength(0);
    appendHeader(b, responseMessage.getMessageID());
    b.append("     Delete Response Protocol Op:").append(StaticUtils.EOL);

    final DeleteResponseProtocolOp protocolOp =
         responseMessage.getDeleteResponseProtocolOp();
    appendResponse(b, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs());

    appendControls(b, responseMessage.getControls());
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processExtendedRequest(final int messageID,
                          @NotNull final ExtendedRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Extended Request Protocol Op:").append(StaticUtils.EOL);
    b.append("          Request OID:  ").append(request.getOID()).
         append(StaticUtils.EOL);

    final ASN1OctetString requestValue = request.getValue();
    if (requestValue != null)
    {
      b.append("          Encoded Request Value:");
      b.append(StaticUtils.EOL);
      StaticUtils.toHexPlusASCII(requestValue.getValue(), 15, b);
    }

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final LDAPMessage responseMessage = requestHandler.processExtendedRequest(
         messageID, request, controls);

    b.setLength(0);
    appendHeader(b, responseMessage.getMessageID());
    b.append("     Extended Response Protocol Op:").append(StaticUtils.EOL);

    final ExtendedResponseProtocolOp protocolOp =
         responseMessage.getExtendedResponseProtocolOp();
    appendResponse(b, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs());

    final String responseOID = protocolOp.getResponseOID();
    if (responseOID != null)
    {
      b.append("          Response OID:  ").append(responseOID).
           append(StaticUtils.EOL);
    }

    final ASN1OctetString responseValue = protocolOp.getResponseValue();
    if (responseValue != null)
    {
      b.append("          Encoded Response Value:");
      b.append(StaticUtils.EOL);
      StaticUtils.toHexPlusASCII(responseValue.getValue(), 15, b);
    }

    appendControls(b, responseMessage.getControls());
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processModifyRequest(final int messageID,
                          @NotNull final ModifyRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Modify Request Protocol Op:").append(StaticUtils.EOL);

    final LDIFModifyChangeRecord changeRecord =
         new LDIFModifyChangeRecord(request.getDN(),
              request.getModifications());
    final String[] ldifLines = changeRecord.toLDIF(80);
    for (final String line : ldifLines)
    {
      b.append("          ").append(line).append(StaticUtils.EOL);
    }

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final LDAPMessage responseMessage = requestHandler.processModifyRequest(
         messageID, request, controls);

    b.setLength(0);
    appendHeader(b, responseMessage.getMessageID());
    b.append("     Modify Response Protocol Op:").append(StaticUtils.EOL);

    final ModifyResponseProtocolOp protocolOp =
         responseMessage.getModifyResponseProtocolOp();
    appendResponse(b, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs());

    appendControls(b, responseMessage.getControls());
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processModifyDNRequest(final int messageID,
                          @NotNull final ModifyDNRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Modify DN Request Protocol Op:").append(StaticUtils.EOL);
    b.append("          DN:  ").append(request.getDN()).append(StaticUtils.EOL);
    b.append("          New RDN:  ").append(request.getNewRDN()).
         append(StaticUtils.EOL);
    b.append("          Delete Old RDN:  ").append(request.deleteOldRDN()).
         append(StaticUtils.EOL);

    final String newSuperior = request.getNewSuperiorDN();
    if (newSuperior != null)
    {
      b.append("          New Superior DN:  ").append(newSuperior).
           append(StaticUtils.EOL);
    }

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final LDAPMessage responseMessage = requestHandler.processModifyDNRequest(
         messageID, request, controls);

    b.setLength(0);
    appendHeader(b, responseMessage.getMessageID());
    b.append("     Modify DN Response Protocol Op:").append(StaticUtils.EOL);

    final ModifyDNResponseProtocolOp protocolOp =
         responseMessage.getModifyDNResponseProtocolOp();
    appendResponse(b, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs());

    appendControls(b, responseMessage.getControls());
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processSearchRequest(final int messageID,
                          @NotNull final SearchRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Search Request Protocol Op:").append(StaticUtils.EOL);
    b.append("          Base DN:  ").append(request.getBaseDN()).
         append(StaticUtils.EOL);
    b.append("          Scope:  ").append(request.getScope()).
         append(StaticUtils.EOL);
    b.append("          Dereference Policy:  ").
         append(request.getDerefPolicy()).append(StaticUtils.EOL);
    b.append("          Size Limit:  ").append(request.getSizeLimit()).
         append(StaticUtils.EOL);
    b.append("          Time Limit:  ").append(request.getSizeLimit()).
         append(StaticUtils.EOL);
    b.append("          Types Only:  ").append(request.typesOnly()).
         append(StaticUtils.EOL);
    b.append("          Filter:  ");
    request.getFilter().toString(b);
    b.append(StaticUtils.EOL);

    final List<String> attributes = request.getAttributes();
    if (! attributes.isEmpty())
    {
      b.append("          Requested Attributes:").append(StaticUtils.EOL);
      for (final String attr : attributes)
      {
        b.append("               ").append(attr).append(StaticUtils.EOL);
      }
    }

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    final LDAPMessage responseMessage = requestHandler.processSearchRequest(
         messageID, request, controls);

    b.setLength(0);
    appendHeader(b, responseMessage.getMessageID());
    b.append("     Search Result Done Protocol Op:").append(StaticUtils.EOL);

    final SearchResultDoneProtocolOp protocolOp =
         responseMessage.getSearchResultDoneProtocolOp();
    appendResponse(b, protocolOp.getResultCode(),
         protocolOp.getDiagnosticMessage(),
         protocolOp.getMatchedDN(), protocolOp.getReferralURLs());

    appendControls(b, responseMessage.getControls());
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return responseMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processUnbindRequest(final int messageID,
                   @NotNull final UnbindRequestProtocolOp request,
                   @NotNull final List<Control> controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Unbind Request Protocol Op:").append(StaticUtils.EOL);

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    requestHandler.processUnbindRequest(messageID, request, controls);
  }



  /**
   * Retrieves a {@code StringBuilder} that may be used to generate a log
   * message.
   *
   * @return  A {@code StringBuilder} containing the LDAP message header.
   */
  @NotNull()
  private static StringBuilder getBuffer()
  {
    StringBuilder b = BUFFERS.get();
    if (b == null)
    {
      b = new StringBuilder();
      BUFFERS.set(b);
    }
    else
    {
      b.setLength(0);
    }

    return b;
  }



  /**
   * Appends an LDAP message header to the provided buffer.
   *
   * @param  b          The buffer to which to write the header.
   * @param  messageID  The message ID for the LDAP message.
   */
  private void appendHeader(@NotNull final StringBuilder b, final int messageID)
  {
    b.append(headerString);
    b.append("LDAP Message:").append(StaticUtils.EOL);
    b.append("     Message ID:  ").append(messageID).append(StaticUtils.EOL);
  }



  /**
   * Appends information about an LDAP response to the given buffer.
   *
   * @param  b                  The buffer to which to append the information.
   * @param  resultCode         The result code for the response.
   * @param  diagnosticMessage  The diagnostic message for the response, if any.
   * @param  matchedDN          The matched DN for the response, if any.
   * @param  referralURLs       The referral URLs for the response, if any.
   */
  private static void appendResponse(@NotNull final StringBuilder b,
                                     final int resultCode,
                                     @Nullable final String diagnosticMessage,
                                     @Nullable final String matchedDN,
                                     @NotNull final List<String> referralURLs)
  {
    b.append("          Result Code:  ").append(ResultCode.valueOf(resultCode)).
         append(StaticUtils.EOL);

    if (diagnosticMessage != null)
    {
      b.append("          Diagnostic Message:  ").append(diagnosticMessage).
           append(StaticUtils.EOL);
    }

    if (matchedDN != null)
    {
      b.append("          Matched DN:  ").append(matchedDN).
           append(StaticUtils.EOL);
    }

    if (! referralURLs.isEmpty())
    {
      b.append("          Referral URLs:").append(StaticUtils.EOL);
      for (final String url : referralURLs)
      {
        b.append("               ").append(url).append(StaticUtils.EOL);
      }
    }
  }



  /**
   * Appends information about the provided set of controls to the given buffer.
   * A trailing EOL will also be appended.
   *
   * @param  b         The buffer to which to append the control information.
   * @param  controls  The set of controls to be appended to the buffer.
   */
  private static void appendControls(@NotNull final StringBuilder b,
                                     @NotNull final List<Control> controls)
  {
    if (! controls.isEmpty())
    {
      b.append("     Controls:").append(StaticUtils.EOL);

      int index = 1;
      for (final Control c : controls)
      {
        b.append("          Control ");
        b.append(index++);
        b.append(StaticUtils.EOL);
        b.append("               OID:  ");
        b.append(c.getOID());
        b.append(StaticUtils.EOL);
        b.append("               Is Critical:  ");
        b.append(c.isCritical());
        b.append(StaticUtils.EOL);

        final ASN1OctetString value = c.getValue();
        if ((value != null) && (value.getValueLength() > 0))
        {
          b.append("               Encoded Value:");
          b.append(StaticUtils.EOL);
          StaticUtils.toHexPlusASCII(value.getValue(), 20, b);
        }

        // If it is a subclass of Control rather than just a generic one, then
        // it might have a useful toString representation, so provide it.
        if (! c.getClass().getName().equals(Control.class.getName()))
        {
          b.append("               String Representation:  ");
          c.toString(b);
          b.append(StaticUtils.EOL);
        }
      }
    }
  }



  /**
   * Appends information about the provided set of controls to the given buffer.
   *
   * @param  b         The buffer to which to append the control information.
   * @param  controls  The set of controls to be appended to the buffer.
   */
  private static void appendControls(@NotNull final StringBuilder b,
                                     @NotNull final Control[] controls)
  {
    appendControls(b, Arrays.asList(controls));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ObjectPair<IntermediateResponseProtocolOp,Control[]>
              transformIntermediateResponse(final int messageID,
                   @NotNull final IntermediateResponseProtocolOp response,
                   @NotNull final Control[] controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Intermediate Response Protocol Op:").append(StaticUtils.EOL);

    final String oid = response.getOID();
    if (oid != null)
    {
      b.append("          OID:  ").append(oid).append(StaticUtils.EOL);
    }

    final ASN1OctetString value = response.getValue();
    if (value != null)
    {
      b.append("          Encoded Value:");
      b.append(StaticUtils.EOL);
      StaticUtils.toHexPlusASCII(value.getValue(), 15, b);
    }

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return new ObjectPair<>(response, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ObjectPair<SearchResultEntryProtocolOp,Control[]> transformEntry(
              final int messageID,
              @NotNull final SearchResultEntryProtocolOp entry,
              @NotNull final Control[] controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Search Result Entry Protocol Op:").append(StaticUtils.EOL);

    final Entry e = new Entry(entry.getDN(), entry.getAttributes());
    final String[] ldifLines = e.toLDIF(80);
    for (final String line : ldifLines)
    {
      b.append("          ").append(line).append(StaticUtils.EOL);
    }

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return new ObjectPair<>(entry, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ObjectPair<SearchResultReferenceProtocolOp,Control[]>
              transformReference(final int messageID,
                   @NotNull final SearchResultReferenceProtocolOp reference,
                   @NotNull final Control[] controls)
  {
    final StringBuilder b = getBuffer();
    appendHeader(b, messageID);

    b.append("     Search Result Reference Protocol Op:").
         append(StaticUtils.EOL);
    b.append("          Referral URLs:").append(StaticUtils.EOL);

    for (final String url : reference.getReferralURLs())
    {
      b.append("               ").append(url).append(StaticUtils.EOL);
    }

    appendControls(b, controls);
    logHandler.publish(new LogRecord(Level.INFO, b.toString()));
    logHandler.flush();

    return new ObjectPair<>(reference, controls);
  }
}
