/*
 * Copyright 2011-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2018 Ping Identity Corporation
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



import java.io.OutputStream;
import java.util.List;
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.ldap.protocol.AbandonRequestProtocolOp;
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.UnbindRequestProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.Debug;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides a request handler implementation that can be used to
 * convert an existing connection to use TLS encryption.  It will handle
 * StartTLS extended operations directly, but will pass all other requests and
 * responses through to another request handler.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class StartTLSRequestHandler
       extends LDAPListenerRequestHandler
{
  // The client connection with which this request handler is associated.
  private final LDAPListenerClientConnection connection;

  // The request handler that will be used to process all operations except the
  // StartTLS extended operation.
  private final LDAPListenerRequestHandler requestHandler;

  // The SSL socket factory that will be used to SSL-enable the existing socket.
  private final SSLSocketFactory sslSocketFactory;



  /**
   * Creates a new StartTLS request handler with the provided information.
   *
   * @param  sslSocketFactory  The SSL socket factory that will be used to
   *                           convert the existing socket to use SSL
   *                           encryption.
   * @param  requestHandler    The request handler that will be used to process
   *                           all operations except StartTLS extended
   *                           operations.
   */
  public StartTLSRequestHandler(final SSLSocketFactory sslSocketFactory,
                                final LDAPListenerRequestHandler requestHandler)
  {
    this.sslSocketFactory = sslSocketFactory;
    this.requestHandler   = requestHandler;

    connection = null;
  }



  /**
   * Creates a new StartTLS request handler with the provided information.
   *
   * @param  sslSocketFactory  The SSL socket factory that will be used to
   *                           convert the existing socket to use SSL
   *                           encryption.
   * @param  requestHandler    The request handler that will be used to process
   *                           all operations except StartTLS extended
   *                           operations.
   * @param  connection        The connection to the associated client.
   */
  private StartTLSRequestHandler(final SSLSocketFactory sslSocketFactory,
               final LDAPListenerRequestHandler requestHandler,
               final LDAPListenerClientConnection connection)
  {
    this.sslSocketFactory = sslSocketFactory;
    this.requestHandler   = requestHandler;
    this.connection       = connection;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public StartTLSRequestHandler
              newInstance(final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    return new StartTLSRequestHandler(sslSocketFactory,
         requestHandler.newInstance(connection), connection);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void closeInstance()
  {
    requestHandler.closeInstance();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processAbandonRequest(final int messageID,
                                    final AbandonRequestProtocolOp request,
                                    final List<Control> controls)
  {
    requestHandler.processAbandonRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processAddRequest(final int messageID,
                                       final AddRequestProtocolOp request,
                                       final List<Control> controls)
  {
    return requestHandler.processAddRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processBindRequest(final int messageID,
                                        final BindRequestProtocolOp request,
                                        final List<Control> controls)
  {
    return requestHandler.processBindRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processCompareRequest(final int messageID,
                          final CompareRequestProtocolOp request,
                          final List<Control> controls)
  {
    return requestHandler.processCompareRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processDeleteRequest(final int messageID,
                                          final DeleteRequestProtocolOp request,
                                          final List<Control> controls)
  {
    return requestHandler.processDeleteRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processExtendedRequest(final int messageID,
                          final ExtendedRequestProtocolOp request,
                          final List<Control> controls)
  {
    if (request.getOID().equals(StartTLSExtendedRequest.STARTTLS_REQUEST_OID))
    {
      try
      {
        // Make sure we can decode the request as a valid StartTLS request.
        final StartTLSExtendedRequest startTLSRequest =
             new StartTLSExtendedRequest(new ExtendedRequest(request.getOID(),
                  request.getValue()));

        final OutputStream clearOutputStream =
             connection.convertToTLS(sslSocketFactory);

        final LDAPMessage responseMessage = new LDAPMessage(messageID,
             new ExtendedResponseProtocolOp(ResultCode.SUCCESS_INT_VALUE, null,
                  null, null, null, null));
        final ASN1Buffer buffer = new ASN1Buffer();
        responseMessage.writeTo(buffer);

        try
        {
          buffer.writeTo(clearOutputStream);
          clearOutputStream.flush();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          final LDAPException le = new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_START_TLS_REQUEST_HANDLER_WRITE_RESPONSE_FAILURE.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
          connection.close(le);
          throw le;
        }

        return responseMessage;
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        return new LDAPMessage(messageID,
             new ExtendedResponseProtocolOp(le.getResultCode().intValue(),
                  le.getMatchedDN(), le.getDiagnosticMessage(),
                  StaticUtils.toList(le.getReferralURLs()), null, null),
             le.getResponseControls());
      }
    }
    else
    {
      return requestHandler.processExtendedRequest(messageID, request,
           controls);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processModifyRequest(final int messageID,
                                          final ModifyRequestProtocolOp request,
                                          final List<Control> controls)
  {
    return requestHandler.processModifyRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processModifyDNRequest(final int messageID,
                          final ModifyDNRequestProtocolOp request,
                          final List<Control> controls)
  {
    return requestHandler.processModifyDNRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPMessage processSearchRequest(final int messageID,
                                          final SearchRequestProtocolOp request,
                                          final List<Control> controls)
  {
    return requestHandler.processSearchRequest(messageID, request, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processUnbindRequest(final int messageID,
                                   final UnbindRequestProtocolOp request,
                                   final List<Control> controls)
  {
    requestHandler.processUnbindRequest(messageID, request, controls);
  }
}
