/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.ldap.protocol.ProtocolOp;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.LDAPSDKUsageException;
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

  // The password provider that should be used to obtain the password for this
  // simple bind request.
  private final PasswordProvider passwordProvider;



  /**
   * Creates a new simple bind request that may be used to perform an anonymous
   * bind to the directory server (i.e., with a zero-length bind DN and a
   * zero-length password).
   */
  public SimpleBindRequest()
  {
    this(NO_BIND_DN, NO_PASSWORD, null, NO_CONTROLS);
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

    passwordProvider = null;
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

    passwordProvider = null;
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

    passwordProvider = null;
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

    passwordProvider = null;
  }



  /**
   * Creates a new simple bind request with the provided bind DN and that will
   * use a password provider in order to obtain the bind password.
   *
   * @param  bindDN            The bind DN for this simple bind request.  It
   *                           must not be {@code null}.
   * @param  passwordProvider  The password provider that will be used to obtain
   *                           the password for this simple bind request.  It
   *                           must not be {@code null}.
   * @param  controls          The set of controls for this simple bind request.
   */
  public SimpleBindRequest(final String bindDN,
                           final PasswordProvider passwordProvider,
                           final Control... controls)
  {
    super(controls);

    this.bindDN           = new ASN1OctetString(bindDN);
    this.passwordProvider = passwordProvider;

    password = null;
  }



  /**
   * Creates a new simple bind request with the provided bind DN and that will
   * use a password provider in order to obtain the bind password.
   *
   * @param  bindDN            The bind DN for this simple bind request.  It
   *                           must not be {@code null}.
   * @param  passwordProvider  The password provider that will be used to obtain
   *                           the password for this simple bind request.  It
   *                           must not be {@code null}.
   * @param  controls          The set of controls for this simple bind request.
   */
  public SimpleBindRequest(final DN bindDN,
                           final PasswordProvider passwordProvider,
                           final Control... controls)
  {
    super(controls);

    this.bindDN           = new ASN1OctetString(bindDN.toString());
    this.passwordProvider = passwordProvider;

    password = null;
  }



  /**
   * Creates a new simple bind request with the provided bind DN and password.
   *
   * @param  bindDN            The bind DN for this simple bind request.
   * @param  password          The password for this simple bind request.
   * @param  passwordProvider  The password provider that will be used to obtain
   *                           the password to use for the bind request.
   * @param  controls          The set of controls for this simple bind request.
   */
  private SimpleBindRequest(final ASN1OctetString bindDN,
                            final ASN1OctetString password,
                            final PasswordProvider passwordProvider,
                            final Control... controls)
  {
    super(controls);

    this.bindDN           = bindDN;
    this.password         = password;
    this.passwordProvider = passwordProvider;
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
   * Retrieves the password for this simple bind request, if no password
   * provider has been configured.
   *
   * @return  The password for this simple bind request, or {@code null} if a
   *          password provider will be used to obtain the password.
   */
  public ASN1OctetString getPassword()
  {
    return password;
  }



  /**
   * Retrieves the password provider for this simple bind request, if defined.
   *
   * @return  The password provider for this simple bind request, or
   *          {@code null} if this bind request was created with an explicit
   *          password rather than a password provider.
   */
  public PasswordProvider getPasswordProvider()
  {
    return passwordProvider;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(final ASN1Buffer buffer)
  {
    final ASN1BufferSequence requestSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST);
    buffer.addElement(VERSION_ELEMENT);
    buffer.addElement(bindDN);

    if (passwordProvider == null)
    {
      buffer.addElement(password);
    }
    else
    {
      final byte[] pwBytes;
      try
      {
        pwBytes = passwordProvider.getPasswordBytes();
      }
      catch (final LDAPException le)
      {
        debugException(le);
        throw new LDAPRuntimeException(le);
      }

      final ASN1OctetString pw = new ASN1OctetString(CRED_TYPE_SIMPLE, pwBytes);
      buffer.addElement(pw);
      buffer.setZeroBufferOnClear();
      Arrays.fill(pwBytes, (byte) 0x00);
    }

    requestSequence.end();
  }



  /**
   * {@inheritDoc}
   * Use of this method is only supported if the bind request was created with a
   * static password.  It is not allowed if the password will be obtained
   * through a password provider.
   *
   * @throws  LDAPSDKUsageException  If this bind request was created with a
   *                                 password provider rather than a static
   *                                 password.
   */
  @Override()
  public ASN1Element encodeProtocolOp()
         throws LDAPSDKUsageException
  {
    if (password == null)
    {
      throw new LDAPSDKUsageException(
           ERR_SIMPLE_BIND_ENCODE_PROTOCOL_OP_WITH_PROVIDER.get());
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
         new ASN1Integer(3),
         bindDN,
         password);
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
      @SuppressWarnings("deprecation")
      final boolean autoReconnect =
           connection.getConnectionOptions().autoReconnect();
      return processSync(connection, autoReconnect);
    }

    // See if a bind DN was provided without a password.  If that is the case
    // and this should not be allowed, then throw an exception.
    if (password != null)
    {
      if ((bindDN.getValue().length > 0) && (password.getValue().length == 0) &&
           connection.getConnectionOptions().bindWithDNRequiresPassword())
      {
        final LDAPException le = new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SIMPLE_BIND_DN_WITHOUT_PASSWORD.get());
        debugCodingError(le);
        throw le;
      }
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
      final long responseTimeout = getResponseTimeoutMillis(connection);
      debugLDAPRequest(Level.INFO, this, messageID, connection);
      final long requestTime = System.nanoTime();
      connection.getConnectionStatistics().incrementNumBindRequests();
      connection.sendMessage(message, responseTimeout);

      // Wait for and process the response.
      final LDAPResponse response;
      try
      {
        if (responseTimeout > 0)
        {
          response = responseQueue.poll(responseTimeout, TimeUnit.MILLISECONDS);
        }
        else
        {
          response = responseQueue.take();
        }
      }
      catch (final InterruptedException ie)
      {
        debugException(ie);
        Thread.currentThread().interrupt();
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_BIND_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response, requestTime, false);
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
   * @param  allowRetry  Indicates whether the request may be re-tried on a
   *                     re-established connection if the initial attempt fails
   *                     in a way that indicates the connection is no longer
   *                     valid and autoReconnect is true.
   *
   * @return  An LDAP result object that provides information about the result
   *          of the bind processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  private BindResult processSync(final LDAPConnection connection,
                                 final boolean allowRetry)
          throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message =
         new LDAPMessage(messageID, this, getControls());


    // Send the request to the server.
    final long requestTime = System.nanoTime();
    debugLDAPRequest(Level.INFO, this, messageID, connection);
    connection.getConnectionStatistics().incrementNumBindRequests();
    try
    {
      connection.sendMessage(message, getResponseTimeoutMillis(connection));
    }
    catch (final LDAPException le)
    {
      debugException(le);

      if (allowRetry)
      {
        final BindResult bindResult = reconnectAndRetry(connection,
             le.getResultCode());
        if (bindResult != null)
        {
          return bindResult;
        }
      }

      throw le;
    }

    while (true)
    {
      final LDAPResponse response = connection.readResponse(messageID);
      if (response instanceof IntermediateResponse)
      {
        final IntermediateResponseListener listener =
             getIntermediateResponseListener();
        if (listener != null)
        {
          listener.intermediateResponseReturned(
               (IntermediateResponse) response);
        }
      }
      else
      {
        return handleResponse(connection, response, requestTime, allowRetry);
      }
    }
  }



  /**
   * Performs the necessary processing for handling a response.
   *
   * @param  connection   The connection used to read the response.
   * @param  response     The response to be processed.
   * @param  requestTime  The time the request was sent to the server.
   * @param  allowRetry   Indicates whether the request may be re-tried on a
   *                      re-established connection if the initial attempt fails
   *                      in a way that indicates the connection is no longer
   *                      valid and autoReconnect is true.
   *
   * @return  The bind result.
   *
   * @throws  LDAPException  If a problem occurs.
   */
  private BindResult handleResponse(final LDAPConnection connection,
                                    final LDAPResponse response,
                                    final long requestTime,
                                    final boolean allowRetry)
          throws LDAPException
  {
    if (response == null)
    {
      final long waitTime = nanosToMillis(System.nanoTime() - requestTime);
      throw new LDAPException(ResultCode.TIMEOUT,
           ERR_SIMPLE_BIND_CLIENT_TIMEOUT.get(waitTime, messageID,
                bindDN.stringValue(), connection.getHostPort()));
    }

    connection.getConnectionStatistics().incrementNumBindResponses(
         System.nanoTime() - requestTime);
    if (response instanceof ConnectionClosedResponse)
    {
      // The connection was closed while waiting for the response.
      if (allowRetry)
      {
        final BindResult retryResult = reconnectAndRetry(connection,
             ResultCode.SERVER_DOWN);
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String message = ccr.getMessage();
      if (message == null)
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_BIND_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_BIND_RESPONSE_WITH_MESSAGE.get(
                  connection.getHostPort(), toString(), message));
      }
    }

    final BindResult bindResult = (BindResult) response;
    if (allowRetry)
    {
      final BindResult retryResult = reconnectAndRetry(connection,
           bindResult.getResultCode());
      if (retryResult != null)
      {
        return retryResult;
      }
    }

    return bindResult;
  }



  /**
   * Attempts to re-establish the connection and retry processing this request
   * on it.
   *
   * @param  connection  The connection to be re-established.
   * @param  resultCode  The result code for the previous operation attempt.
   *
   * @return  The result from re-trying the bind, or {@code null} if it could
   *          not be re-tried.
   */
  private BindResult reconnectAndRetry(final LDAPConnection connection,
                                       final ResultCode resultCode)
  {
    try
    {
      // We will only want to retry for certain result codes that indicate a
      // connection problem.
      switch (resultCode.intValue())
      {
        case ResultCode.SERVER_DOWN_INT_VALUE:
        case ResultCode.DECODING_ERROR_INT_VALUE:
        case ResultCode.CONNECT_ERROR_INT_VALUE:
          connection.reconnect();
          return processSync(connection, false);
      }
    }
    catch (final Exception e)
    {
      debugException(e);
    }

    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public SimpleBindRequest getRebindRequest(final String host, final int port)
  {
    return new SimpleBindRequest(bindDN, password, passwordProvider,
         getControls());
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void responseReceived(final LDAPResponse response)
         throws LDAPException
  {
    try
    {
      responseQueue.put(response);
    }
    catch (final Exception e)
    {
      debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }

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
         new SimpleBindRequest(bindDN, password, passwordProvider, controls);
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



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toCode(final List<String> lineList, final String requestID,
                     final int indentSpaces, final boolean includeProcessing)
  {
    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs =
         new ArrayList<ToCodeArgHelper>(3);
    constructorArgs.add(ToCodeArgHelper.createString(bindDN.stringValue(),
         "Bind DN"));
    constructorArgs.add(ToCodeArgHelper.createString("---redacted-password---",
         "Bind Password"));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, "SimpleBindRequest",
         requestID + "Request", "new SimpleBindRequest", constructorArgs);


    // Add lines for processing the request and obtaining the result.
    if (includeProcessing)
    {
      // Generate a string with the appropriate indent.
      final StringBuilder buffer = new StringBuilder();
      for (int i=0; i < indentSpaces; i++)
      {
        buffer.append(' ');
      }
      final String indent = buffer.toString();

      lineList.add("");
      lineList.add(indent + "try");
      lineList.add(indent + '{');
      lineList.add(indent + "  BindResult " + requestID +
           "Result = connection.bind(" + requestID + "Request);");
      lineList.add(indent + "  // The bind was processed successfully.");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (LDAPException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The bind failed.  Maybe the following will " +
           "help explain why.");
      lineList.add(indent + "  // Note that the connection is now likely in " +
           "an unauthenticated state.");
      lineList.add(indent + "  ResultCode resultCode = e.getResultCode();");
      lineList.add(indent + "  String message = e.getMessage();");
      lineList.add(indent + "  String matchedDN = e.getMatchedDN();");
      lineList.add(indent + "  String[] referralURLs = e.getReferralURLs();");
      lineList.add(indent + "  Control[] responseControls = " +
           "e.getResponseControls();");
      lineList.add(indent + '}');
    }
  }
}
