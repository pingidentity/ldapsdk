/*
 * Copyright 2007-2010 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2010 UnboundID Corp.
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



import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.ldap.protocol.ProtocolOp;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class implements the processing necessary to perform an LDAPv3 simple
 * bind operation, which authenticates using a bind DN and password.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class SimpleBindRequest
       extends BindRequest
       implements ResponseAcceptor, ProtocolOp
{
  /**
   * The BER type to use for the credentials element in a simple bind request
   * protocol op.
   */
  private static final byte CRED_TYPE_SIMPLE = (byte) 0x80;



  /**
   * The ASN.1 octet string that will be used for the bind DN if none was
   * provided.
   */
  private static final ASN1OctetString NO_BIND_DN = new ASN1OctetString();



  /**
   * The ASN.1 octet string that will be used for the bind password if none was
   * provided.
   */
  private static final ASN1OctetString NO_PASSWORD =
       new ASN1OctetString(CRED_TYPE_SIMPLE);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4725871243149974407L;



  // The message ID from the last LDAP message sent from this request.
  private int messageID = -1;

  // The bind DN for this simple bind request.
  private final ASN1OctetString bindDN;

  // The password for this simple bind request.
  private final ASN1OctetString password;

  // The queue that will be used to receive response messages from the server.
  private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<LDAPResponse>();



  /**
   * Creates a new simple bind request that may be used to perform an anonymous
   * bind to the directory server (i.e., with a zero-length bind DN and a
   * zero-length password).
   */
  public SimpleBindRequest()
  {
    this(NO_BIND_DN, NO_PASSWORD, NO_CONTROLS);
  }



  /**
   * Creates a new simple bind request with the provided bind DN and password.
   *
   * @param  bindDN    The bind DN for this simple bind request.
   * @param  password  The password for this simple bind request.
   */
  public SimpleBindRequest(final String bindDN, final String password)
  {
    this(bindDN, password, NO_CONTROLS);
  }



  /**
   * Creates a new simple bind request with the provided bind DN and password.
   *
   * @param  bindDN    The bind DN for this simple bind request.
   * @param  password  The password for this simple bind request.
   */
  public SimpleBindRequest(final String bindDN, final byte[] password)
  {
    this(bindDN, password, NO_CONTROLS);
  }



  /**
   * Creates a new simple bind request with the provided bind DN and password.
   *
   * @param  bindDN    The bind DN for this simple bind request.
   * @param  password  The password for this simple bind request.
   */
  public SimpleBindRequest(final DN bindDN, final String password)
  {
    this(bindDN, password, NO_CONTROLS);
  }



  /**
   * Creates a new simple bind request with the provided bind DN and password.
   *
   * @param  bindDN    The bind DN for this simple bind request.
   * @param  password  The password for this simple bind request.
   */
  public SimpleBindRequest(final DN bindDN, final byte[] password)
  {
    this(bindDN, password, NO_CONTROLS);
  }



  /**
   * Creates a new simple bind request with the provided bind DN and password.
   *
   * @param  bindDN    The bind DN for this simple bind request.
   * @param  password  The password for this simple bind request.
   * @param  controls  The set of controls for this simple bind request.
   */
  public SimpleBindRequest(final String bindDN, final String password,
                           final Control... controls)
  {
    super(controls);

    if (bindDN == null)
    {
      this.bindDN = NO_BIND_DN;
    }
    else
    {
      this.bindDN = new ASN1OctetString(bindDN);
    }

    if (password == null)
    {
      this.password = NO_PASSWORD;
    }
    else
    {
      this.password = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }
  }



  /**
   * Creates a new simple bind request with the provided bind DN and password.
   *
   * @param  bindDN    The bind DN for this simple bind request.
   * @param  password  The password for this simple bind request.
   * @param  controls  The set of controls for this simple bind request.
   */
  public SimpleBindRequest(final String bindDN, final byte[] password,
                           final Control... controls)
  {
    super(controls);

    if (bindDN == null)
    {
      this.bindDN = NO_BIND_DN;
    }
    else
    {
      this.bindDN = new ASN1OctetString(bindDN);
    }

    if (password == null)
    {
      this.password = NO_PASSWORD;
    }
    else
    {
      this.password = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }
  }



  /**
   * Creates a new simple bind request with the provided bind DN and password.
   *
   * @param  bindDN    The bind DN for this simple bind request.
   * @param  password  The password for this simple bind request.
   * @param  controls  The set of controls for this simple bind request.
   */
  public SimpleBindRequest(final DN bindDN, final String password,
                           final Control... controls)
  {
    super(controls);

    if (bindDN == null)
    {
      this.bindDN = NO_BIND_DN;
    }
    else
    {
      this.bindDN = new ASN1OctetString(bindDN.toString());
    }

    if (password == null)
    {
      this.password = NO_PASSWORD;
    }
    else
    {
      this.password = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }
  }



  /**
   * Creates a new simple bind request with the provided bind DN and password.
   *
   * @param  bindDN    The bind DN for this simple bind request.
   * @param  password  The password for this simple bind request.
   * @param  controls  The set of controls for this simple bind request.
   */
  public SimpleBindRequest(final DN bindDN, final byte[] password,
                           final Control... controls)
  {
    super(controls);

    if (bindDN == null)
    {
      this.bindDN = NO_BIND_DN;
    }
    else
    {
      this.bindDN = new ASN1OctetString(bindDN.toString());
    }

    if (password == null)
    {
      this.password = NO_PASSWORD;
    }
    else
    {
      this.password = new ASN1OctetString(CRED_TYPE_SIMPLE, password);
    }
  }



  /**
   * Creates a new simple bind request with the provided bind DN and password.
   *
   * @param  bindDN    The bind DN for this simple bind request.
   * @param  password  The password for this simple bind request.
   * @param  controls  The set of controls for this simple bind request.
   */
  SimpleBindRequest(final ASN1OctetString bindDN,
                    final ASN1OctetString password, final Control... controls)
  {
    super(controls);

    this.bindDN   = bindDN;
    this.password = password;
  }



  /**
   * Retrieves the bind DN for this simple bind request.
   *
   * @return  The bind DN for this simple bind request.
   */
  public String getBindDN()
  {
    return bindDN.stringValue();
  }



  /**
   * Retrieves the password for this simple bind request.
   *
   * @return  The password for this simple bind request.
   */
  public ASN1OctetString getPassword()
  {
    return password;
  }



  /**
   * {@inheritDoc}
   */
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence requestSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST);
    buffer.addElement(VERSION_ELEMENT);
    buffer.addElement(bindDN);
    buffer.addElement(password);
    requestSequence.end();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      return processSync(connection);
    }

    // See if a bind DN was provided without a password.  If that is the case
    // and this should not be allowed, then throw an exception.
    if ((bindDN.getValue().length > 0) && (password.getValue().length == 0) &&
        connection.getConnectionOptions().bindWithDNRequiresPassword())
    {
      final LDAPException le = new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SIMPLE_BIND_DN_WITHOUT_PASSWORD.get());
      debugCodingError(le);
      throw le;
    }


    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message = new LDAPMessage(messageID, this, getControls());


    // Register with the connection reader to be notified of responses for the
    // request that we've created.
    connection.registerResponseAcceptor(messageID, this);


    try
    {
      // Send the request to the server.
      debugLDAPRequest(this);
      final long requestTime = System.nanoTime();
      connection.getConnectionStatistics().incrementNumBindRequests();
      connection.sendMessage(message);

      // Wait for and process the response.
      final LDAPResponse response;
      try
      {
        final long responseTimeout = getResponseTimeoutMillis(connection);
        if (responseTimeout > 0)
        {
          response = responseQueue.poll(responseTimeout, TimeUnit.MILLISECONDS);
        }
        else
        {
          response = responseQueue.take();
        }
      }
      catch (InterruptedException ie)
      {
        debugException(ie);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_BIND_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response, requestTime);
    }
    finally
    {
      connection.deregisterResponseAcceptor(messageID);
    }
  }



  /**
   * Processes this bind operation in synchronous mode, in which the same
   * thread will send the request and read the response.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   *
   * @return  An LDAP result object that provides information about the result
   *          of the bind processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  private BindResult processSync(final LDAPConnection connection)
          throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message =
         new LDAPMessage(messageID,  this, getControls());


    // Set the appropriate timeout on the socket.
    try
    {
      connection.getConnectionInternals().getSocket().setSoTimeout(
           (int) getResponseTimeoutMillis(connection));
    }
    catch (Exception e)
    {
      debugException(e);
    }


    // Send the request to the server.
    final long requestTime = System.nanoTime();
    debugLDAPRequest(this);
    connection.getConnectionStatistics().incrementNumBindRequests();
    connection.sendMessage(message);

    final LDAPResponse response = connection.readResponse(messageID);
    return handleResponse(connection, response, requestTime);
  }



  /**
   * Performs the necessary processing for handling a response.
   *
   * @param  connection   The connection used to read the response.
   * @param  response     The response to be processed.
   * @param  requestTime  The time the request was sent to the server.
   *
   * @return  The bind result.
   *
   * @throws  LDAPException  If a problem occurs.
   */
  private BindResult handleResponse(final LDAPConnection connection,
                                    final LDAPResponse response,
                                    final long requestTime)
          throws LDAPException
  {
    if (response == null)
    {
      final long waitTime = System.currentTimeMillis() - requestTime;
      throw new LDAPException(ResultCode.TIMEOUT,
           ERR_BIND_CLIENT_TIMEOUT.get(waitTime, connection.getHostPort()));
    }

    connection.getConnectionStatistics().incrementNumBindResponses(
         System.nanoTime() - requestTime);
    if (response instanceof ConnectionClosedResponse)
    {
      // The connection was closed while waiting for the response.
      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String message = ccr.getMessage();
      if (message == null)
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_CONN_CLOSED_WAITING_FOR_BIND_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_CONN_CLOSED_WAITING_FOR_BIND_RESPONSE_WITH_MESSAGE.get(
                  connection.getHostPort(), toString(), message));
      }
    }

    return (BindResult) response;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SimpleBindRequest getRebindRequest(final String host, final int port)
  {
    return new SimpleBindRequest(bindDN, password, getControls());
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  public void responseReceived(final LDAPResponse response)
         throws LDAPException
  {
    try
    {
      responseQueue.put(response);
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_EXCEPTION_HANDLING_RESPONSE.get(getExceptionMessage(e)), e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getBindType()
  {
    return "SIMPLE";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SimpleBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SimpleBindRequest duplicate(final Control[] controls)
  {
    final SimpleBindRequest bindRequest =
         new SimpleBindRequest(bindDN, password, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("SimpleBindRequest(dn='");
    buffer.append(bindDN);
    buffer.append('\'');

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
