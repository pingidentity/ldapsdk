/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener.interceptor;



import java.util.List;
import java.util.HashMap;
import java.util.Map;

import com.unboundid.ldap.listener.IntermediateResponseTransformer;
import com.unboundid.ldap.listener.LDAPListenerClientConnection;
import com.unboundid.ldap.listener.LDAPListenerRequestHandler;
import com.unboundid.ldap.listener.SearchEntryTransformer;
import com.unboundid.ldap.listener.SearchReferenceTransformer;
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
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.listener.interceptor.InterceptorMessages.*;



/**
 * This class provides an LDAP listener request handler that may be used to
 * invoke any in-memory operation interceptors in the course of processing
 * operations for the in-memory directory server.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class InMemoryOperationInterceptorRequestHandler
       extends LDAPListenerRequestHandler
       implements IntermediateResponseTransformer, SearchEntryTransformer,
                  SearchReferenceTransformer
{
  // The set of interceptors to be used to transform requests and responses.
  @NotNull private final InMemoryOperationInterceptor[] interceptors;

  // The client connection associated with this request handler instance.
  @Nullable private final LDAPListenerClientConnection connection;

  // The request handler that will be used to ensure that operations actually
  // get processed.
  @NotNull private final LDAPListenerRequestHandler wrappedHandler;

  // A map containing active operations mapped by message ID.
  @NotNull private final Map<Integer,InterceptedOperation> activeOperations;



  /**
   * Creates a new instance of this LDAP listener request handler that will be
   * used to process the provided set of operation interceptors.
   *
   * @param  interceptors    The set of operation interceptors that will be used
   *                         to transform requests and responses.  If there are
   *                         multiple interceptors, then they will be invoked in
   *                         the same order as elements in the provided list
   *                         when processing both requests and results.
   * @param  wrappedHandler  The request handler that will be used to ensure
   *                         that operations actually get processed.
   */
  public InMemoryOperationInterceptorRequestHandler(
              @NotNull final List<InMemoryOperationInterceptor> interceptors,
              @NotNull final LDAPListenerRequestHandler wrappedHandler)
  {
    this.wrappedHandler = wrappedHandler;

    this.interceptors = new InMemoryOperationInterceptor[interceptors.size()];
    interceptors.toArray(this.interceptors);

    connection       = null;
    activeOperations = new HashMap<>(StaticUtils.computeMapCapacity(5));
  }



  /**
   * Creates a new instance of this LDAP listener request handler that will be
   * used to process the provided set of operation interceptors.
   *
   * @param  interceptors    The set of operation interceptors that will be used
   *                         to transform requests and responses.  If there are
   *                         multiple interceptors, then they will be invoked in
   *                         the same order as elements in the provided list
   *                         when processing both requests and results.
   * @param  wrappedHandler  The request handler that will be used to ensure
   *                         that operations actually get processed.
   * @param  connection      The client connection associated with this request
   *                         handler instance.
   */
  private InMemoryOperationInterceptorRequestHandler(
               @NotNull final InMemoryOperationInterceptor[] interceptors,
               @NotNull final LDAPListenerRequestHandler wrappedHandler,
               @NotNull final LDAPListenerClientConnection connection)
  {
    this.interceptors   = interceptors;
    this.wrappedHandler = wrappedHandler;
    this.connection     = connection;

    activeOperations = new HashMap<>(StaticUtils.computeMapCapacity(5));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public InMemoryOperationInterceptorRequestHandler newInstance(
              @NotNull final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    final InMemoryOperationInterceptorRequestHandler handler =
         new InMemoryOperationInterceptorRequestHandler(interceptors,
              wrappedHandler.newInstance(connection), connection);

    connection.addSearchEntryTransformer(handler);
    connection.addSearchReferenceTransformer(handler);
    connection.addIntermediateResponseTransformer(handler);

    return handler;
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
    final InterceptedAddOperation op = new InterceptedAddOperation(connection,
         messageID, request, toArray(controls));
    activeOperations.put(messageID, op);

    try
    {
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processAddRequest(op);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          return new LDAPMessage(messageID,
               new AddResponseProtocolOp(le.toLDAPResult()),
               le.getResponseControls());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new AddResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_REQUEST_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null
               )
          );
        }
      }

      final LDAPMessage resultMessage = wrappedHandler.processAddRequest(
           messageID,
           new AddRequestProtocolOp((AddRequest) op.getRequest()),
           op.getRequest().getControlList());
      op.setResult(resultMessage.getAddResponseProtocolOp().toLDAPResult(
           toArray(resultMessage.getControls())));
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processAddResult(op);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new AddResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_RESULT_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null
               )
          );
        }
      }

      return new LDAPMessage(messageID,
           new AddResponseProtocolOp(op.getResult()),
           op.getResult().getResponseControls());
    }
    finally
    {
      activeOperations.remove(messageID);
    }
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
    if (request.getCredentialsType() == BindRequestProtocolOp.CRED_TYPE_SIMPLE)
    {
      final InterceptedSimpleBindOperation op =
           new InterceptedSimpleBindOperation(connection, messageID, request,
                toArray(controls));
      activeOperations.put(messageID, op);

      try
      {
        for (final InMemoryOperationInterceptor i : interceptors)
        {
          try
          {
            i.processSimpleBindRequest(op);
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            return new LDAPMessage(messageID,
                 new BindResponseProtocolOp(le.toLDAPResult()),
                 le.getResponseControls());
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            return new LDAPMessage(messageID,
                 new BindResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                      ERR_DS_INTERCEPTOR_REQUEST_ERROR.get(
                           String.valueOf(op), i.getClass().getName(),
                           StaticUtils.getExceptionMessage(e)),
                      null, null));
          }
        }

        final LDAPMessage resultMessage = wrappedHandler.processBindRequest(
             messageID,
             new BindRequestProtocolOp(op.getRequest()),
             op.getRequest().getControlList());
        op.setResult(resultMessage.getBindResponseProtocolOp().toBindResult(
             toArray(resultMessage.getControls())));
        for (final InMemoryOperationInterceptor i : interceptors)
        {
          try
          {
            i.processSimpleBindResult(op);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            return new LDAPMessage(messageID,
                 new BindResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                      ERR_DS_INTERCEPTOR_RESULT_ERROR.get(
                           String.valueOf(op), i.getClass().getName(),
                           StaticUtils.getExceptionMessage(e)),
                      null, null));
          }
        }

        return new LDAPMessage(messageID,
             new BindResponseProtocolOp(op.getResult()),
             op.getResult().getResponseControls());
      }
      finally
      {
        activeOperations.remove(messageID);
      }
    }
    else
    {
      final InterceptedSASLBindOperation op =
           new InterceptedSASLBindOperation(connection, messageID, request,
                toArray(controls));
      activeOperations.put(messageID, op);

      try
      {
        for (final InMemoryOperationInterceptor i : interceptors)
        {
          try
          {
            i.processSASLBindRequest(op);
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            return new LDAPMessage(messageID,
                 new BindResponseProtocolOp(le.toLDAPResult()),
                 le.getResponseControls());
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            return new LDAPMessage(messageID,
                 new BindResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                      ERR_DS_INTERCEPTOR_REQUEST_ERROR.get(
                           String.valueOf(op), i.getClass().getName(),
                           StaticUtils.getExceptionMessage(e)),
                      null, null));
          }
        }

        final LDAPMessage resultMessage = wrappedHandler.processBindRequest(
             messageID,
             new BindRequestProtocolOp(op.getRequest()),
             op.getRequest().getControlList());
        op.setResult(resultMessage.getBindResponseProtocolOp().toBindResult(
             toArray(resultMessage.getControls())));
        for (final InMemoryOperationInterceptor i : interceptors)
        {
          try
          {
            i.processSASLBindResult(op);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            return new LDAPMessage(messageID,
                 new BindResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                      ERR_DS_INTERCEPTOR_RESULT_ERROR.get(
                           String.valueOf(op), i.getClass().getName(),
                           StaticUtils.getExceptionMessage(e)),
                      null, null));
          }
        }

        return new LDAPMessage(messageID,
             new BindResponseProtocolOp(op.getResult()),
             op.getResult().getResponseControls());
      }
      finally
      {
        activeOperations.remove(messageID);
      }
    }
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
    final InterceptedCompareOperation op =
         new InterceptedCompareOperation(connection, messageID, request,
              toArray(controls));
    activeOperations.put(messageID, op);

    try
    {
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processCompareRequest(op);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          return new LDAPMessage(messageID,
               new CompareResponseProtocolOp(le.toLDAPResult()),
               le.getResponseControls());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new CompareResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_REQUEST_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null));
        }
      }

      final LDAPMessage resultMessage = wrappedHandler.processCompareRequest(
           messageID,
           new CompareRequestProtocolOp((CompareRequest) op.getRequest()),
           op.getRequest().getControlList());
      op.setResult(resultMessage.getCompareResponseProtocolOp().toLDAPResult(
           toArray(resultMessage.getControls())));
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processCompareResult(op);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new CompareResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_RESULT_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null));
        }
      }

      return new LDAPMessage(messageID,
           new CompareResponseProtocolOp(op.getResult()),
           op.getResult().getResponseControls());
    }
    finally
    {
      activeOperations.remove(messageID);
    }
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
    final InterceptedDeleteOperation op =
         new InterceptedDeleteOperation(connection, messageID, request,
              toArray(controls));
    activeOperations.put(messageID, op);

    try
    {
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processDeleteRequest(op);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          return new LDAPMessage(messageID,
               new DeleteResponseProtocolOp(le.toLDAPResult()),
               le.getResponseControls());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new DeleteResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_REQUEST_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null));
        }
      }

      final LDAPMessage resultMessage = wrappedHandler.processDeleteRequest(
           messageID,
           new DeleteRequestProtocolOp((DeleteRequest) op.getRequest()),
           op.getRequest().getControlList());
      op.setResult(resultMessage.getDeleteResponseProtocolOp().toLDAPResult(
           toArray(resultMessage.getControls())));
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processDeleteResult(op);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new DeleteResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_RESULT_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null));
        }
      }

      return new LDAPMessage(messageID,
           new DeleteResponseProtocolOp(op.getResult()),
           op.getResult().getResponseControls());
    }
    finally
    {
      activeOperations.remove(messageID);
    }
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
    final InterceptedExtendedOperation op =
         new InterceptedExtendedOperation(connection, messageID, request,
              toArray(controls));
    activeOperations.put(messageID, op);

    try
    {
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processExtendedRequest(op);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          return new LDAPMessage(messageID,
               new ExtendedResponseProtocolOp(le.toLDAPResult()),
               le.getResponseControls());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new ExtendedResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_REQUEST_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null, null, null));
        }
      }

      final LDAPMessage resultMessage = wrappedHandler.processExtendedRequest(
           messageID,
           new ExtendedRequestProtocolOp(op.getRequest()),
           op.getRequest().getControlList());
      op.setResult(
           resultMessage.getExtendedResponseProtocolOp().toExtendedResult(
                toArray(resultMessage.getControls())));
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processExtendedResult(op);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new ExtendedResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_RESULT_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null, null, null));
        }
      }

      return new LDAPMessage(messageID,
           new ExtendedResponseProtocolOp(op.getResult()),
           op.getResult().getResponseControls());
    }
    finally
    {
      activeOperations.remove(messageID);
    }
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
    final InterceptedModifyOperation op =
         new InterceptedModifyOperation(connection, messageID, request,
              toArray(controls));
    activeOperations.put(messageID, op);

    try
    {
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processModifyRequest(op);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          return new LDAPMessage(messageID,
               new ModifyResponseProtocolOp(le.toLDAPResult()),
               le.getResponseControls());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new ModifyResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_REQUEST_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null));
        }
      }

      final LDAPMessage resultMessage = wrappedHandler.processModifyRequest(
           messageID,
           new ModifyRequestProtocolOp((ModifyRequest) op.getRequest()),
           op.getRequest().getControlList());
      op.setResult(resultMessage.getModifyResponseProtocolOp().toLDAPResult(
           toArray(resultMessage.getControls())));
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processModifyResult(op);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new ModifyResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_RESULT_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null));
        }
      }

      return new LDAPMessage(messageID,
           new ModifyResponseProtocolOp(op.getResult()),
           op.getResult().getResponseControls());
    }
    finally
    {
      activeOperations.remove(messageID);
    }
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
    final InterceptedModifyDNOperation op =
         new InterceptedModifyDNOperation(connection, messageID, request,
              toArray(controls));
    activeOperations.put(messageID, op);

    try
    {
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processModifyDNRequest(op);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          return new LDAPMessage(messageID,
               new ModifyDNResponseProtocolOp(le.toLDAPResult()),
               le.getResponseControls());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new ModifyDNResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_REQUEST_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null));
        }
      }

      final LDAPMessage resultMessage = wrappedHandler.processModifyDNRequest(
           messageID,
           new ModifyDNRequestProtocolOp((ModifyDNRequest) op.getRequest()),
           op.getRequest().getControlList());
      op.setResult(resultMessage.getModifyDNResponseProtocolOp().toLDAPResult(
           toArray(resultMessage.getControls())));
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processModifyDNResult(op);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new ModifyDNResponseProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_RESULT_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null));
        }
      }

      return new LDAPMessage(messageID,
           new ModifyDNResponseProtocolOp(op.getResult()),
           op.getResult().getResponseControls());
    }
    finally
    {
      activeOperations.remove(messageID);
    }
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
    final InterceptedSearchOperation op =
         new InterceptedSearchOperation(connection, messageID, request,
              toArray(controls));
    activeOperations.put(messageID, op);

    try
    {
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processSearchRequest(op);
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          return new LDAPMessage(messageID,
               new SearchResultDoneProtocolOp(le.toLDAPResult()),
               le.getResponseControls());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new SearchResultDoneProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_REQUEST_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null));
        }
      }

      final LDAPMessage resultMessage = wrappedHandler.processSearchRequest(
           messageID,
           new SearchRequestProtocolOp((SearchRequest) op.getRequest()),
           op.getRequest().getControlList());
      op.setResult(resultMessage.getSearchResultDoneProtocolOp().toLDAPResult(
           toArray(resultMessage.getControls())));
      for (final InMemoryOperationInterceptor i : interceptors)
      {
        try
        {
          i.processSearchResult(op);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new LDAPMessage(messageID,
               new SearchResultDoneProtocolOp(ResultCode.OTHER_INT_VALUE, null,
                    ERR_DS_INTERCEPTOR_RESULT_ERROR.get(
                         String.valueOf(op), i.getClass().getName(),
                         StaticUtils.getExceptionMessage(e)),
                    null));
        }
      }

      return new LDAPMessage(messageID,
           new SearchResultDoneProtocolOp(op.getResult()),
           op.getResult().getResponseControls());
    }
    finally
    {
      activeOperations.remove(messageID);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public ObjectPair<SearchResultEntryProtocolOp,Control[]> transformEntry(
              final int messageID,
              @NotNull final SearchResultEntryProtocolOp entry,
              @NotNull final Control[] controls)
  {
    final InterceptedSearchOperation op =
         (InterceptedSearchOperation) activeOperations.get(messageID);
    if (op == null)
    {
      return new ObjectPair<>(entry, controls);
    }

    final InterceptedSearchEntry e =
         new InterceptedSearchEntry(op, entry, controls);
    for (final InMemoryOperationInterceptor i : interceptors)
    {
      try
      {
        i.processSearchEntry(e);
        if (e.getSearchEntry() == null)
        {
          return null;
        }
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
        return null;
      }
    }

    return new ObjectPair<>(new SearchResultEntryProtocolOp(e.getSearchEntry()),
         e.getSearchEntry().getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public ObjectPair<SearchResultReferenceProtocolOp,Control[]>
              transformReference(final int messageID,
                   @NotNull final SearchResultReferenceProtocolOp reference,
                   @NotNull final Control[] controls)
  {
    final InterceptedSearchOperation op =
         (InterceptedSearchOperation) activeOperations.get(messageID);
    if (op == null)
    {
      return new ObjectPair<>(reference, controls);
    }

    final InterceptedSearchReference r =
         new InterceptedSearchReference(op, reference, controls);
    for (final InMemoryOperationInterceptor i : interceptors)
    {
      try
      {
        i.processSearchReference(r);
        if (r.getSearchReference() == null)
        {
          return null;
        }
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
        return null;
      }
    }

    return new ObjectPair<>(
         new SearchResultReferenceProtocolOp(r.getSearchReference()),
         r.getSearchReference().getControls());
  }



  /**
   * Transforms the provided intermediate response and/or set of controls to
   * alter what will be returned to the client.
   *
   * @param  messageID  The message ID for the associated search operation.
   * @param  response   The intermediate response to be processed.  It will not
   *                    be {@code null}.
   * @param  controls   The set of controls to be processed.  It will not be
   *                    {@code null} but may be empty if there are no controls.
   *
   * @return  An {@link ObjectPair} containing a possibly updated intermediate
   *          response and set of controls, or {@code null} to indicate that the
   *          response should not be returned to the client.
   */
  @Override()
  @Nullable()
  public ObjectPair<IntermediateResponseProtocolOp,Control[]>
              transformIntermediateResponse(final int messageID,
                   @NotNull final IntermediateResponseProtocolOp response,
                   @NotNull final Control[] controls)
  {
    final InterceptedOperation op = activeOperations.get(messageID);
    if (op == null)
    {
      return new ObjectPair<>(response, controls);
    }

    final InterceptedIntermediateResponse r =
         new InterceptedIntermediateResponse(op, response, controls);
    for (final InMemoryOperationInterceptor i : interceptors)
    {
      try
      {
        i.processIntermediateResponse(r);
        if (r.getIntermediateResponse() == null)
        {
          return null;
        }
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
        return null;
      }
    }

    return new ObjectPair<>(
         new IntermediateResponseProtocolOp(r.getIntermediateResponse()),
         r.getIntermediateResponse().getControls());
  }



  /**
   * Converts the provided control list to a control array.
   *
   * @param  controls  The list of controls to be converted to an array.
   *
   * @return  The resulting array of controls.
   */
  @NotNull()
  private static Control[] toArray(@NotNull final List<Control> controls)
  {
    if ((controls == null) || controls.isEmpty())
    {
      return StaticUtils.NO_CONTROLS;
    }

    final Control[] controlArray = new Control[controls.size()];
    return controls.toArray(controlArray);
  }
}
