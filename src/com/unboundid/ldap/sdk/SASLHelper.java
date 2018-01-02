/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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



import java.util.List;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

import com.unboundid.asn1.ASN1OctetString;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a mechanism for authenticating to an LDAP directory
 * server using the Java SASL client library.  It is intended for internal use
 * only.
 */
final class SASLHelper
{
  // The set of controls to include in the request.
  private final Control[] controls;

  // The message ID used when communicating with the directory server.
  private volatile int messageID;

  // The connection to use to communicate with the directory server.
  private final LDAPConnection connection;

  // A list that will be updated with messages about any unhandled callbacks
  // encountered during processing.
  private final List<String> unhandledCallbackMessages;

  // The maximum length of time in milliseconds to wait for a response from the
  // server.
  private final long responseTimeoutMillis;

  // The SASL bind request being processed.
  private final SASLBindRequest bindRequest;

  // The SASL client to use to perform the processing.
  private final SaslClient saslClient;

  // The name of the SASL mechanism to use.
  private final String mechanism;



  /**
   * Creates a new SASL client with the provided information.
   *
   * @param  bindRequest                The SASL bind request being processed.
   * @param  connection                 The connection to use to communicate
   *                                    with the directory server.
   * @param  mechanism                  The name of the SASL mechanism to use.
   * @param  saslClient                 The Java SASL client instance to use to
   *                                    perform the processing.
   * @param  controls                   The set of controls to include in the
   *                                    request.
   * @param  responseTimeoutMillis      The maximum length of time in
   *                                    milliseconds to wait for a response from
   *                                    the server.
   * @param  unhandledCallbackMessages  A list that will be updated with
   *                                    messages about any unhandled callbacks.
   */
  SASLHelper(final SASLBindRequest bindRequest, final LDAPConnection connection,
             final String mechanism, final SaslClient saslClient,
             final Control[] controls, final long responseTimeoutMillis,
             final List<String> unhandledCallbackMessages)
  {
    this.bindRequest               = bindRequest;
    this.connection                = connection;
    this.mechanism                 = mechanism;
    this.saslClient                = saslClient;
    this.controls                  = controls;
    this.responseTimeoutMillis     = responseTimeoutMillis;
    this.unhandledCallbackMessages = unhandledCallbackMessages;

    messageID = -1;
  }



  /**
   * Performs a SASL bind against an LDAP directory server.
   *
   * @return  The result of the bind operation processing.
   *
   * @throws  LDAPException  If a problem occurs while processing the bind.
   */
  BindResult processSASLBind()
         throws LDAPException
  {
    try
    {
      // Get the SASL credentials for the initial request.
      byte[] credBytes = null;
      try
      {
        if (saslClient.hasInitialResponse())
        {
          credBytes = saslClient.evaluateChallenge(new byte[0]);
        }
      }
      catch (final Exception e)
      {
        debugException(e);
        if (unhandledCallbackMessages.isEmpty())
        {
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_SASL_CANNOT_CREATE_INITIAL_REQUEST.get(mechanism,
                    getExceptionMessage(e)), e);
        }
        else
        {
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_SASL_CANNOT_CREATE_INITIAL_REQUEST_UNHANDLED_CALLBACKS.get(
                    mechanism, getExceptionMessage(e),
                    concatenateStrings(unhandledCallbackMessages)),
               e);
        }
      }

      ASN1OctetString saslCredentials;
      if ((credBytes == null) || (credBytes.length == 0))
      {
        saslCredentials = null;
      }
      else
      {
        saslCredentials = new ASN1OctetString(credBytes);
      }

      BindResult bindResult = bindRequest.sendBindRequest(connection, "",
           saslCredentials, controls, responseTimeoutMillis);
      messageID = bindRequest.getLastMessageID();

      if (! bindResult.getResultCode().equals(ResultCode.SASL_BIND_IN_PROGRESS))
      {
        return bindResult;
      }

      byte[] serverCredBytes;
      ASN1OctetString serverCreds = bindResult.getServerSASLCredentials();
      if (serverCreds == null)
      {
        serverCredBytes = null;
      }
      else
      {
        serverCredBytes = serverCreds.getValue();
      }

      while (true)
      {
        try
        {
          credBytes = saslClient.evaluateChallenge(serverCredBytes);
        }
        catch (final Exception e)
        {
          debugException(e);
          if (unhandledCallbackMessages.isEmpty())
          {
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_SASL_CANNOT_CREATE_SUBSEQUENT_REQUEST.get(mechanism,
                      getExceptionMessage(e)), e);
          }
          else
          {
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_SASL_CANNOT_CREATE_SUBSEQUENT_REQUEST_UNHANDLED_CALLBACKS.
                      get(mechanism, getExceptionMessage(e),
                           concatenateStrings(unhandledCallbackMessages)),
                 e);
          }
        }

        // Create the bind request protocol op.
        if ((credBytes == null) || (credBytes.length == 0))
        {
          saslCredentials = null;
        }
        else
        {
          saslCredentials = new ASN1OctetString(credBytes);
        }

        bindResult = bindRequest.sendBindRequest(connection, "",
             saslCredentials, controls, responseTimeoutMillis);
        messageID = bindRequest.getLastMessageID();
        if (! bindResult.getResultCode().equals(
                   ResultCode.SASL_BIND_IN_PROGRESS))
        {
          // Even if this is the final response, the server credentials may
          // still have information useful to the SASL client (e.g., cipher
          // information to use for applying quality of protection).  Feed that
          // to the SASL client.
          final ASN1OctetString serverCredentials =
               bindResult.getServerSASLCredentials();
          if (serverCredentials != null)
          {
            try
            {
              saslClient.evaluateChallenge(serverCredentials.getValue());
            }
            catch (final Exception e)
            {
              debugException(e);
            }
          }

          return bindResult;
        }

        serverCreds = bindResult.getServerSASLCredentials();
        if (serverCreds == null)
        {
          serverCredBytes = null;
        }
        else
        {
          serverCredBytes = serverCreds.getValue();
        }
      }
    }
    finally
    {
      boolean hasNegotiatedSecurity = false;
      if (saslClient.isComplete())
      {
        final Object qopObject = saslClient.getNegotiatedProperty(Sasl.QOP);
        if (qopObject != null)
        {
          final String qopString = toLowerCase(String.valueOf(qopObject));
          if (qopString.contains(SASLQualityOfProtection.AUTH_INT.toString()) ||
               qopString.contains(SASLQualityOfProtection.AUTH_CONF.toString()))
          {
            hasNegotiatedSecurity = true;
          }
        }
      }

      if (hasNegotiatedSecurity)
      {
        connection.applySASLQoP(saslClient);
      }
      else
      {
        try
        {
          saslClient.dispose();
        }
        catch (final Exception e)
        {
          debugException(e);
        }
      }
    }
  }



  /**
   * Retrieves the message ID used when communicating with the directory server.
   *
   * @return  The message ID used when communicating with the directory server.
   */
  int getMessageID()
  {
    return messageID;
  }
}
