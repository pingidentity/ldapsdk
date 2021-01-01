/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import com.unboundid.ldap.protocol.AbandonRequestProtocolOp;
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.UnbindRequestProtocolOp;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.ToCodeArgHelper;
import com.unboundid.ldap.sdk.ToCodeHelper;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a request handler that may be used to create a log file
 * with code that may be used to generate the requests received from clients.
 * It will be also be associated with another request handler that will actually
 * be used to handle the request.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ToCodeRequestHandler
       extends LDAPListenerRequestHandler
{
  // Indicates whether any messages have been written to the log so far.
  @NotNull private final AtomicBoolean firstMessage;

  // Indicates whether the output should include code that may be used to
  // process the request and handle the response.
  private final boolean includeProcessing;

  // The client connection with which this request handler is associated.
  @Nullable private final LDAPListenerClientConnection clientConnection;

  // The request handler that actually will be used to process any requests
  // received.
  @NotNull private final LDAPListenerRequestHandler requestHandler;

  // The stream to which the generated code will be written.
  @NotNull private final PrintStream logStream;

  // Thread-local lists used to hold the generated code.
  @NotNull private final ThreadLocal<List<String>> lineLists;



  /**
   * Creates a new LDAP listener request handler that will write a log file with
   * LDAP SDK code that corresponds to requests received from clients.  The
   * requests will be forwarded on to another request handler for further
   * processing.
   *
   * @param  outputFilePath     The path to the output file to be which the
   *                            generated code should be written.  It must not
   *                            be {@code null}, and the parent directory must
   *                            exist.  If a file already exists with the
   *                            specified path, then new generated code will be
   *                            appended to it.
   * @param  includeProcessing  Indicates whether the output should include
   *                            sample code for processing the request and
   *                            handling the response.
   * @param  requestHandler     The request handler that will actually be used
   *                            to process any requests received.  It must not
   *                            be {@code null}.
   *
   * @throws  IOException  If a problem is encountered while opening the
   *                       output file for writing.
   */
  public ToCodeRequestHandler(@NotNull final String outputFilePath,
              final boolean includeProcessing,
              @NotNull final LDAPListenerRequestHandler requestHandler)
         throws IOException
  {
    this(new File(outputFilePath), includeProcessing, requestHandler);
  }



  /**
   * Creates a new LDAP listener request handler that will write a log file with
   * LDAP SDK code that corresponds to requests received from clients.  The
   * requests will be forwarded on to another request handler for further
   * processing.
   *
   * @param  outputFile         The output file to be which the generated code
   *                            should be written.  It must not be {@code null},
   *                            and the parent directory must exist.  If the
   *                            file already exists, then new generated code
   *                            will be appended to it.
   * @param  includeProcessing  Indicates whether the output should include
   *                            sample code for processing the request and
   *                            handling the response.
   * @param  requestHandler     The request handler that will actually be used
   *                            to process any requests received.  It must not
   *                            be {@code null}.
   *
   * @throws  IOException  If a problem is encountered while opening the
   *                       output file for writing.
   */
  public ToCodeRequestHandler(@NotNull final File outputFile,
              final boolean includeProcessing,
              @NotNull final LDAPListenerRequestHandler requestHandler)
         throws IOException
  {
    this(new FileOutputStream(outputFile, true), includeProcessing,
         requestHandler);
  }



  /**
   * Creates a new LDAP listener request handler that will write a log file with
   * LDAP SDK code that corresponds to requests received from clients.  The
   * requests will be forwarded on to another request handler for further
   * processing.
   *
   * @param  outputStream       The output stream to which the generated code
   *                            will be written.  It must not be {@code null}.
   * @param  includeProcessing  Indicates whether the output should include
   *                            sample code for processing the request and
   *                            handling the response.
   * @param  requestHandler     The request handler that will actually be used
   *                            to process any requests received.  It must not
   *                            be {@code null}.
   */
  public ToCodeRequestHandler(@NotNull final OutputStream outputStream,
              final boolean includeProcessing,
              @NotNull final LDAPListenerRequestHandler requestHandler)
  {
    logStream = new PrintStream(outputStream, true);

    this.includeProcessing = includeProcessing;
    this.requestHandler    = requestHandler;

    firstMessage     = new AtomicBoolean(true);
    lineLists        = new ThreadLocal<>();
    clientConnection = null;
  }



  /**
   * Creates a new to code request handler instance for the provided client
   * connection.
   *
   * @param  parentHandler  The parent handler with which this instance will be
   *                        associated.
   * @param  connection     The client connection for this instance.
   *
   * @throws  LDAPException  If a problem is encountered while creating a new
   *                         instance of the downstream request handler.
   */
  private ToCodeRequestHandler(
               @NotNull final ToCodeRequestHandler parentHandler,
               @NotNull final LDAPListenerClientConnection connection)
          throws LDAPException
  {
    logStream         = parentHandler.logStream;
    includeProcessing = parentHandler.includeProcessing;
    requestHandler    = parentHandler.requestHandler.newInstance(connection);
    firstMessage      = parentHandler.firstMessage;
    clientConnection  = connection;
    lineLists         = parentHandler.lineLists;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ToCodeRequestHandler newInstance(
              @NotNull final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    return new ToCodeRequestHandler(this, connection);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void closeInstance()
  {
    // We'll always close the downstream request handler instance.
    requestHandler.closeInstance();


    // We only want to close the log stream if this is the parent instance that
    // is not associated with any specific connection.
    if (clientConnection == null)
    {
      synchronized (logStream)
      {
        logStream.close();
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processAbandonRequest(final int messageID,
                   @NotNull final AbandonRequestProtocolOp request,
                   @NotNull final List<Control> controls)
  {
    // The LDAP SDK doesn't provide an AbandonRequest object.  In order to
    // process abandon operations, the LDAP SDK requires the client to have
    // invoked an asynchronous operation in order to get an AsyncRequestID.
    // Since this uses LDAPConnection.abandon, then that falls  under the
    // "processing" umbrella.  So we'll only log something if we should include
    // processing details.
    if (includeProcessing)
    {
      final List<String> lineList = getLineList(messageID);

      final ArrayList<ToCodeArgHelper> args = new ArrayList<>(2);
      args.add(ToCodeArgHelper.createRaw(
           "asyncRequestID" + request.getIDToAbandon(), "Async Request ID"));
      if (! controls.isEmpty())
      {
        final Control[] controlArray = new Control[controls.size()];
        controls.toArray(controlArray);
        args.add(ToCodeArgHelper.createControlArray(controlArray,
             "Request Controls"));
      }

      ToCodeHelper.generateMethodCall(lineList, 0, null, null,
           "connection.abandon", args);

      writeLines(lineList);
    }

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
    final List<String> lineList = getLineList(messageID);

    final String requestID = "conn" + clientConnection.getConnectionID() +
         "Msg" + messageID + "Add";
    final AddRequest addRequest =
         request.toAddRequest(getControlArray(controls));
    addRequest.toCode(lineList, requestID, 0, includeProcessing);
    writeLines(lineList);

    return requestHandler.processAddRequest(messageID, request, controls);
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
    final List<String> lineList = getLineList(messageID);

    final String requestID = "conn" + clientConnection.getConnectionID() +
         "Msg" + messageID + "Bind";
    final BindRequest bindRequest =
         request.toBindRequest(getControlArray(controls));
    bindRequest.toCode(lineList, requestID, 0, includeProcessing);
    writeLines(lineList);

    return requestHandler.processBindRequest(messageID, request, controls);
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
    final List<String> lineList = getLineList(messageID);

    final String requestID = "conn" + clientConnection.getConnectionID() +
         "Msg" + messageID + "Compare";
    final CompareRequest compareRequest =
         request.toCompareRequest(getControlArray(controls));
    compareRequest.toCode(lineList, requestID, 0, includeProcessing);
    writeLines(lineList);

    return requestHandler.processCompareRequest(messageID, request, controls);
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
    final List<String> lineList = getLineList(messageID);

    final String requestID = "conn" + clientConnection.getConnectionID() +
         "Msg" + messageID + "Delete";
    final DeleteRequest deleteRequest =
         request.toDeleteRequest(getControlArray(controls));
    deleteRequest.toCode(lineList, requestID, 0, includeProcessing);
    writeLines(lineList);

    return requestHandler.processDeleteRequest(messageID, request, controls);
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
    final List<String> lineList = getLineList(messageID);

    final String requestID = "conn" + clientConnection.getConnectionID() +
         "Msg" + messageID + "Extended";
    final ExtendedRequest extendedRequest =
         request.toExtendedRequest(getControlArray(controls));
    extendedRequest.toCode(lineList, requestID, 0, includeProcessing);
    writeLines(lineList);

    return requestHandler.processExtendedRequest(messageID, request, controls);
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
    final List<String> lineList = getLineList(messageID);

    final String requestID = "conn" + clientConnection.getConnectionID() +
         "Msg" + messageID + "Modify";
    final ModifyRequest modifyRequest =
         request.toModifyRequest(getControlArray(controls));
    modifyRequest.toCode(lineList, requestID, 0, includeProcessing);
    writeLines(lineList);

    return requestHandler.processModifyRequest(messageID, request, controls);
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
    final List<String> lineList = getLineList(messageID);

    final String requestID = "conn" + clientConnection.getConnectionID() +
         "Msg" + messageID + "ModifyDN";
    final ModifyDNRequest modifyDNRequest =
         request.toModifyDNRequest(getControlArray(controls));
    modifyDNRequest.toCode(lineList, requestID, 0, includeProcessing);
    writeLines(lineList);

    return requestHandler.processModifyDNRequest(messageID, request, controls);
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
    final List<String> lineList = getLineList(messageID);

    final String requestID = "conn" + clientConnection.getConnectionID() +
         "Msg" + messageID + "Search";
    final SearchRequest searchRequest =
         request.toSearchRequest(getControlArray(controls));
    searchRequest.toCode(lineList, requestID, 0, includeProcessing);
    writeLines(lineList);

    return requestHandler.processSearchRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processUnbindRequest(final int messageID,
                   @NotNull final UnbindRequestProtocolOp request,
                   @NotNull final List<Control> controls)
  {
    // The LDAP SDK doesn't provide an UnbindRequest object, because it is not
    // possible to separate an unbind request from a connection closure, which
    // is done by using LDAPConnection.close method.  That falls  under the
    // "processing" umbrella, so we'll only log something if we should include
    // processing details.
    if (includeProcessing)
    {
      final List<String> lineList = getLineList(messageID);

      final ArrayList<ToCodeArgHelper> args = new ArrayList<>(1);
      if (! controls.isEmpty())
      {
        final Control[] controlArray = new Control[controls.size()];
        controls.toArray(controlArray);
        args.add(ToCodeArgHelper.createControlArray(controlArray,
             "Request Controls"));
      }

      ToCodeHelper.generateMethodCall(lineList, 0, null, null,
           "connection.close", args);

      writeLines(lineList);
    }

    requestHandler.processUnbindRequest(messageID, request, controls);
  }



  /**
   * Retrieves a list to use to hold the lines of output.  It will include
   * comments with information about the client that submitted the request.
   *
   * @param  messageID  The message ID for the associated request.
   *
   * @return  A list to use to hold the lines of output.
   */
  @NotNull()
  private List<String> getLineList(final int messageID)
  {
    // Get a thread-local string list, creating it if necessary.
    List<String> lineList = lineLists.get();
    if (lineList == null)
    {
      lineList = new ArrayList<>(20);
      lineLists.set(lineList);
    }
    else
    {
      lineList.clear();
    }


    // Add the appropriate header content to the list.
    lineList.add("// Time:  " + new Date());
    lineList.add("// Client Address: " +
         clientConnection.getSocket().getInetAddress().getHostAddress() + ':' +
         clientConnection.getSocket().getPort());
    lineList.add("// Server Address: " +
         clientConnection.getSocket().getLocalAddress().getHostAddress() + ':' +
         clientConnection.getSocket().getLocalPort());
    lineList.add("// Connection ID: " + clientConnection.getConnectionID());
    lineList.add("// Message ID: " + messageID);

    return lineList;
  }



  /**
   * Writes the lines contained in the provided list to the output stream.
   *
   * @param  lineList  The list containing the lines to be written.
   */
  private void writeLines(@NotNull final List<String> lineList)
  {
    synchronized (logStream)
    {
      if (! firstMessage.compareAndSet(true, false))
      {
        logStream.println();
        logStream.println();
      }

      for (final String s : lineList)
      {
        logStream.println(s);
      }
    }
  }



  /**
   * Converts the provided list of controls into an array of controls.
   *
   * @param  controls  The list of controls to convert to an array.
   *
   * @return  An array of controls that corresponds to the provided list.
   */
  @NotNull()
  private static Control[] getControlArray(
               @Nullable final List<Control> controls)
  {
    if ((controls == null) || controls.isEmpty())
    {
      return StaticUtils.NO_CONTROLS;
    }

    final Control[] controlArray = new Control[controls.size()];
    return controls.toArray(controlArray);
  }
}
