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



import java.util.List;

import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.IntermediateResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.ProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultEntryProtocolOp;
import com.unboundid.ldap.protocol.SearchResultReferenceProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides an implementation of a request handler that can be used
 * for testing purposes.
 */
public final class TestRequestHandler
       extends LDAPListenerRequestHandler
{
  // Indicates whether to throw an exception when trying to create a new
  // instance.
  private static boolean throwOnNewInstance = false;

  // Indicates whether to throw an exception when trying to process a request.
  private static boolean throwOnProcessRequest = false;

  // The response controls to return for the next operation.
  private static Control[] returnControls = new Control[0];

  // The intermediate responses to return for the next operation.
  private static IntermediateResponseProtocolOp[] returnIntermediateResponses =
       new IntermediateResponseProtocolOp[0];

  // The client connection for this handler instance.
  private final LDAPListenerClientConnection connection;

  // The next protocol op to return.
  private static ProtocolOp protocolOp = null;

  // The search result entries to return for the next search.
  private static SearchResultEntryProtocolOp[] returnEntries =
  new SearchResultEntryProtocolOp[0];

  // The search result references to return for the next search.
  private static SearchResultReferenceProtocolOp[] returnReferences =
       new SearchResultReferenceProtocolOp[0];



  /**
   * Creates a new instance of this request handler.
   */
  public TestRequestHandler()
  {
    connection = null;
  }



  /**
   * Creates a new instance of this request handler with the provided
   * connection.
   *
   * @param  connection  The connection to use for this request handler.
   */
  private TestRequestHandler(final LDAPListenerClientConnection connection)
  {
    this.connection = connection;
  }



  /**
   * Specifies whether to throw an exception when trying to create a new
   * instance.
   *
   * @param  shouldThrow  Indicates whether to throw an exception when trying to
   *                      create a new instance.
   */
  public static void setThrowOnNewInstance(final boolean shouldThrow)
  {
    throwOnNewInstance = shouldThrow;
  }



  /**
   * Specifies whether to throw an exception when trying to process a new
   * request.
   *
   * @param  shouldThrow  Indicates whether to throw an exception when trying to
   *                      create a new instance.
   */
  public static void setThrowOnProcessRequest(final boolean shouldThrow)
  {
    throwOnProcessRequest = shouldThrow;
  }



  /**
   * Sets the protocol op that should be returned for the next request.
   *
   * @param  op  The protocol op that should be returned for the next request.
   */
  public static void setReturnOp(final ProtocolOp op)
  {
    protocolOp = op;
  }



  /**
   * Sets the controls that should be returned for the next request.
   *
   * @param  controls  The controls that should be returned for the next
   *                   request.
   */
  public static void setControls(final Control... controls)
  {
    returnControls = controls;
  }



  /**
   * Sets the intermediate that should be returned for the next operation.
   *
   * @param  responses  The intermediate responses that should be returned for
   *                    the next operation.
   */
  public static void setReturnIntermediateResponses(
                          final IntermediateResponseProtocolOp... responses)
  {
    returnIntermediateResponses = responses;
  }



  /**
   * Sets the entries that should be returned for the next search.
   *
   * @param  entries  The entries that should be returned for the next search.
   */
  public static void setReturnEntries(
                          final SearchResultEntryProtocolOp... entries)
  {
    returnEntries = entries;
  }



  /**
   * Sets the references that should be returned for the next search.
   *
   * @param  refs  The references that should be returned for the next search.
   */
  public static void setReturnReferences(
                          final SearchResultReferenceProtocolOp... refs)
  {
    returnReferences = refs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public TestRequestHandler newInstance(
                                 final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    if (throwOnNewInstance)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Throwing an exception because " +
                "TestRequestHandler.throwOnNewInstance is true");
    }

    return new TestRequestHandler(connection);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processAddRequest(final int messageID,
                                       final AddRequestProtocolOp request,
                                       final List<Control> controls)
  {
    if (throwOnProcessRequest)
    {
      throw new RuntimeException("Throwing an exception because " +
           "TestRequestHandler.throwOnProcessRequest is true");
    }

    for (final IntermediateResponseProtocolOp op : returnIntermediateResponses)
    {
      try
      {
        connection.sendIntermediateResponse(messageID, op, returnControls);
      } catch (final Exception e) {}
    }

    return new LDAPMessage(messageID, protocolOp);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processBindRequest(final int messageID,
                                        final BindRequestProtocolOp request,
                                        final List<Control> controls)
  {
    if (throwOnProcessRequest)
    {
      throw new RuntimeException("Throwing an exception because " +
           "TestRequestHandler.throwOnProcessRequest is true");
    }

    for (final IntermediateResponseProtocolOp op : returnIntermediateResponses)
    {
      try
      {
        connection.sendIntermediateResponse(messageID, op, returnControls);
      } catch (final Exception e) {}
    }

    return new LDAPMessage(messageID, protocolOp, returnControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processCompareRequest(final int messageID,
                          final CompareRequestProtocolOp request,
                          final List<Control> controls)
  {
    if (throwOnProcessRequest)
    {
      throw new RuntimeException("Throwing an exception because " +
           "TestRequestHandler.throwOnProcessRequest is true");
    }

    for (final IntermediateResponseProtocolOp op : returnIntermediateResponses)
    {
      try
      {
        connection.sendIntermediateResponse(messageID, op, returnControls);
      } catch (final Exception e) {}
    }

    return new LDAPMessage(messageID, protocolOp, returnControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processDeleteRequest(final int messageID,
                                          final DeleteRequestProtocolOp request,
                                          final List<Control> controls)
  {
    if (throwOnProcessRequest)
    {
      throw new RuntimeException("Throwing an exception because " +
           "TestRequestHandler.throwOnProcessRequest is true");
    }

    for (final IntermediateResponseProtocolOp op : returnIntermediateResponses)
    {
      try
      {
        connection.sendIntermediateResponse(messageID, op, returnControls);
      } catch (final Exception e) {}
    }

    return new LDAPMessage(messageID, protocolOp, returnControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processExtendedRequest(final int messageID,
                          final ExtendedRequestProtocolOp request,
                          final List<Control> controls)
  {
    if (throwOnProcessRequest)
    {
      throw new RuntimeException("Throwing an exception because " +
           "TestRequestHandler.throwOnProcessRequest is true");
    }

    for (final IntermediateResponseProtocolOp op : returnIntermediateResponses)
    {
      try
      {
        connection.sendIntermediateResponse(messageID, op, returnControls);
      } catch (final Exception e) {}
    }

    return new LDAPMessage(messageID, protocolOp, returnControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processModifyRequest(final int messageID,
                                          final ModifyRequestProtocolOp request,
                                          final List<Control> controls)
  {
    if (throwOnProcessRequest)
    {
      throw new RuntimeException("Throwing an exception because " +
           "TestRequestHandler.throwOnProcessRequest is true");
    }

    for (final IntermediateResponseProtocolOp op : returnIntermediateResponses)
    {
      try
      {
        connection.sendIntermediateResponse(messageID, op, returnControls);
      } catch (final Exception e) {}
    }

    return new LDAPMessage(messageID, protocolOp, returnControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processModifyDNRequest(final int messageID,
                          final ModifyDNRequestProtocolOp request,
                          final List<Control> controls)
  {
    if (throwOnProcessRequest)
    {
      throw new RuntimeException("Throwing an exception because " +
           "TestRequestHandler.throwOnProcessRequest is true");
    }

    for (final IntermediateResponseProtocolOp op : returnIntermediateResponses)
    {
      try
      {
        connection.sendIntermediateResponse(messageID, op, returnControls);
      } catch (final Exception e) {}
    }

    return new LDAPMessage(messageID, protocolOp, returnControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processSearchRequest(final int messageID,
                                          final SearchRequestProtocolOp request,
                                          final List<Control> controls)
  {
    if (throwOnProcessRequest)
    {
      throw new RuntimeException("Throwing an exception because " +
           "TestRequestHandler.throwOnProcessRequest is true");
    }

    for (final IntermediateResponseProtocolOp op : returnIntermediateResponses)
    {
      try
      {
        connection.sendIntermediateResponse(messageID, op, returnControls);
      } catch (final Exception e) {}
    }

    for (final SearchResultEntryProtocolOp entry : returnEntries)
    {
      try
      {
        connection.sendSearchResultEntry(messageID, entry, returnControls);
      } catch (final Exception e) {}
    }

    for (final SearchResultReferenceProtocolOp ref : returnReferences)
    {
      try
      {
        connection.sendSearchResultReference(messageID, ref, returnControls);
      } catch (final Exception e) {}
    }

    return new LDAPMessage(messageID, protocolOp, returnControls);
  }
}
