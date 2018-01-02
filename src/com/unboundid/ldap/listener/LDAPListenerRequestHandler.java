/*
 * Copyright 2010-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2018 Ping Identity Corporation
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

import com.unboundid.ldap.protocol.AbandonRequestProtocolOp;
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.UnbindRequestProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an API that may be used to process requests read from a
 * client connection.  A separate instance of this class, obtained through the
 * {@link #newInstance} method,  will be used for each connection created by an
 * {@link LDAPListener}.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class LDAPListenerRequestHandler
{
  /**
   * Creates a new instance of this request handler that will be used to process
   * requests read by the provided connection.
   *
   * @param  connection  The connection with which this request handler instance
   *                     will be associated.
   *
   * @return  The request handler instance that will be used for the provided
   *          connection.
   *
   * @throws  LDAPException  If the connection should not be accepted.
   */
  public abstract LDAPListenerRequestHandler newInstance(
                       LDAPListenerClientConnection connection)
         throws LDAPException;



  /**
   * Indicates that the client connection with which this request handler
   * instance is associated is being closed and any resources associated with it
   * should be released.
   */
  public void closeInstance()
  {
    // No implementation is needed by default.
  }



  /**
   * Performs any processing necessary for the provided abandon request.
   *
   * @param  messageID  The message ID of the LDAP message containing the
   *                    abandon request.
   * @param  request    The abandon request that was included in the LDAP
   *                    message that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   */
  public void processAbandonRequest(final int messageID,
                                    final AbandonRequestProtocolOp request,
                                    final List<Control> controls)
  {
    // No implementation provided by default.
  }



  /**
   * Performs any processing necessary for the provided add request.
   *
   * @param  messageID  The message ID of the LDAP message containing the add
   *                    request.
   * @param  request    The add request that was included in the LDAP message
   *                    that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be an
   *          {@code AddResponseProtocolOp}.
   */
  public abstract LDAPMessage processAddRequest(int messageID,
                                   AddRequestProtocolOp request,
                                   List<Control> controls);



  /**
   * Performs any processing necessary for the provided bind request.
   *
   * @param  messageID  The message ID of the LDAP message containing the bind
   *                    request.
   * @param  request    The bind request that was included in the LDAP message
   *                    that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be a
   *          {@code BindResponseProtocolOp}.
   */
  public abstract LDAPMessage processBindRequest(int messageID,
                                   BindRequestProtocolOp request,
                                   List<Control> controls);



  /**
   * Performs any processing necessary for the provided compare request.
   *
   * @param  messageID  The message ID of the LDAP message containing the
   *                    compare request.
   * @param  request    The compare request that was included in the LDAP
   *                    message that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be a
   *          {@code CompareResponseProtocolOp}.
   */
  public abstract LDAPMessage processCompareRequest(int messageID,
                                   CompareRequestProtocolOp request,
                                   List<Control> controls);



  /**
   * Performs any processing necessary for the provided delete request.
   *
   * @param  messageID  The message ID of the LDAP message containing the delete
   *                    request.
   * @param  request    The delete request that was included in the LDAP message
   *                    that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be a
   *          {@code DeleteResponseProtocolOp}.
   */
  public abstract LDAPMessage processDeleteRequest(int messageID,
                                   DeleteRequestProtocolOp request,
                                   List<Control> controls);



  /**
   * Performs any processing necessary for the provided extended request.
   *
   * @param  messageID  The message ID of the LDAP message containing the
   *                    extended request.
   * @param  request    The extended request that was included in the LDAP
   *                    message that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be an
   *          {@code ExtendedResponseProtocolOp}.
   */
  public abstract LDAPMessage processExtendedRequest(int messageID,
                                   ExtendedRequestProtocolOp request,
                                   List<Control> controls);



  /**
   * Performs any processing necessary for the provided modify request.
   *
   * @param  messageID  The message ID of the LDAP message containing the modify
   *                    request.
   * @param  request    The modify request that was included in the LDAP message
   *                    that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be an
   *          {@code ModifyResponseProtocolOp}.
   */
  public abstract LDAPMessage processModifyRequest(int messageID,
                                   ModifyRequestProtocolOp request,
                                   List<Control> controls);



  /**
   * Performs any processing necessary for the provided modify DN request.
   *
   * @param  messageID  The message ID of the LDAP message containing the modify
   *                    DN request.
   * @param  request    The modify DN request that was included in the LDAP
   *                    message that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be an
   *          {@code ModifyDNResponseProtocolOp}.
   */
  public abstract LDAPMessage processModifyDNRequest(int messageID,
                                   ModifyDNRequestProtocolOp request,
                                   List<Control> controls);



  /**
   * Performs any processing necessary for the provided search request.
   *
   * @param  messageID  The message ID of the LDAP message containing the search
   *                    request.
   * @param  request    The search request that was included in the LDAP message
   *                    that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   *
   * @return  The {@link LDAPMessage} containing the response to send to the
   *          client.  The protocol op in the {@code LDAPMessage} must be an
   *          {@code SearchResultDoneProtocolOp}.
   */
  public abstract LDAPMessage processSearchRequest(int messageID,
                                   SearchRequestProtocolOp request,
                                   List<Control> controls);



  /**
   * Performs any processing necessary for the provided unbind request.
   *
   * @param  messageID  The message ID of the LDAP message containing the search
   *                    request.
   * @param  request    The search request that was included in the LDAP message
   *                    that was received.
   * @param  controls   The set of controls included in the LDAP message.  It
   *                    may be empty if there were no controls, but will not be
   *                    {@code null}.
   */
  public void processUnbindRequest(final int messageID,
                                   final UnbindRequestProtocolOp request,
                                   final List<Control> controls)
  {
    // No implementation provided by default.
  }
}
