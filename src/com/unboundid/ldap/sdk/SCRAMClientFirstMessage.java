/*
 * Copyright 2019-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019-2020 Ping Identity Corporation
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



import java.io.Serializable;
import java.security.SecureRandom;

import com.unboundid.util.Base64;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class holds the elements associated with the client first message in a
 * SCRAM authentication sequence.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class SCRAMClientFirstMessage
     implements Serializable
{
  /**
   * The GS2 header indicating that this implementation does not support channel
   * binding.
   */
  private static final String GS2_HEADER_NO_CHANNEL_BINDING = "n,,";



  /**
   * A base64-encoded representation of the GS2 channel binding header.
   */
  private static final String GS2_HEADER_NO_CHANNEL_BINDING_BASE64 =
       Base64.encode(GS2_HEADER_NO_CHANNEL_BINDING);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7117556259158222514L;



  // The bind request being processed.
  private final SCRAMBindRequest bindRequest;

  // The full constructed client first message.
  private final String clientFirstMessage;

  // The bare representation of the client-first message (without the GS2
  // channel binding header).
  private final String clientFirstMessageBare;

  // The client nonce being processed.
  private final String clientNonce;

  // The base64-encoded representation of the GS2 channel binding header.
  private final String gs2HeaderBase64;

  // The raw string representation of the GS2 channel binding header.
  private final String gs2HeaderRaw;



  /**
   * Creates a new client first message with the provided bind request.  A
   * client nonce will be dynamically generated.
   *
   * @param  bindRequest  The SCRAM bind request being processed.  It must not
   *                      be {@code null}.
   */
  SCRAMClientFirstMessage(final SCRAMBindRequest bindRequest)
  {
    this(bindRequest, null);
  }



  /**
   * Creates a new client first message with the provided bind request and
   * client nonce.
   *
   * @param  bindRequest  The SCRAM bind request being processed.  It must not
   *                      be {@code null}.
   * @param  clientNonce  The client nonce to use for the message.  If it is
   *                      {@code null}, then a nonce will be dynamically
   *                      generated.
   */
  SCRAMClientFirstMessage(final SCRAMBindRequest bindRequest,
                          final String clientNonce)
  {
    this.bindRequest = bindRequest;

    if (clientNonce == null)
    {
      final SecureRandom random = new SecureRandom();
      final byte[] clientNonceBytes = new byte[16];
      random.nextBytes(clientNonceBytes);
      this.clientNonce = Base64.urlEncode(clientNonceBytes, false);
    }
    else
    {
      this.clientNonce = clientNonce;
    }

    gs2HeaderRaw = GS2_HEADER_NO_CHANNEL_BINDING;
    gs2HeaderBase64 = GS2_HEADER_NO_CHANNEL_BINDING_BASE64;

    clientFirstMessageBare =
         "n=" + bindRequest.getUsername() + ",r=" + this.clientNonce;
    clientFirstMessage = gs2HeaderRaw + clientFirstMessageBare;
  }



  /**
   * Retrieves the SCRAM bind request being processed.
   *
   * @return  The SCRAM bind request being processed.
   */
  SCRAMBindRequest getBindRequest()
  {
    return bindRequest;
  }



  /**
   * Retrieves the raw string representation of the GS2 channel binding header
   * for this client first message.
   *
   * @return  The raw string representation of the GS2 channel binding header
   *          for this client first message.
   */
  String getGS2HeaderRaw()
  {
    return gs2HeaderRaw;
  }



  /**
   * Retrieves the base64-encoded string representation of the GS2 channel
   * binding header for this client first message.
   *
   * @return  The base64-encoded string representation of the GS2 channel
   *          binding header for this client first message.
   */
  String getGS2HeaderBase64()
  {
    return gs2HeaderBase64;
  }



  /**
   * Retrieves the client nonce string for this client first message.
   *
   * @return  The client nonce string for this client first message.
   */
  String getClientNonce()
  {
    return clientNonce;
  }



  /**
   * Retrieves the full client first message string, including the GS2 channel
   * binding header.
   *
   * @return  The full client first message string.
   */
  String getClientFirstMessage()
  {
    return clientFirstMessage;
  }



  /**
   * Retrieves the bare client first message string, without the GS2 channel
   * binding header.
   *
   * @return  The bare client first message string.
   */
  String getClientFirstMessageBare()
  {
    return clientFirstMessageBare;
  }



  /**
   * Retrieves a string representation of this SCRAM client first message.
   *
   * @return  A string representation of this SCRAM client first message.
   */
  @Override()
  public String toString()
  {
    return clientFirstMessage;
  }
}
