/*
 * Copyright 2007-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2022 Ping Identity Corporation
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
 * Copyright (C) 2007-2022 Ping Identity Corporation
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
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.NTLM;

import static com.unboundid.ldap.sdk.LDAPMessages.*;

public class NTLMBindRequest extends SimpleBindRequest {

    /**
     * The serial version UID for this serializable class.
     */
    private static final long serialVersionUID = 4725961243149974401L;

    private final String username;
    private final String password;
    private final String domain;
    private int messageID = -1;

    public LDAPConnection connection;

    public NTLM ntlm;
    public byte[] type3Message;

    // The queue that will be used to receive response messages from the server.
    @NotNull
    private final LinkedBlockingQueue<LDAPResponse> responseQueue = new LinkedBlockingQueue<>();

    public NTLMBindRequest(String username, String password, String domain) {
        super();
        this.username = username;
        this.password = password;
        this.domain = domain;
    }

    /**
     * {@inheritDoc}
     */
    @Override()
    @NotNull()
    protected BindResult process(@NotNull final LDAPConnection connection,
            final int depth)
            throws LDAPException {

        this.connection = connection;

        if (connection.synchronousMode()) {
            @SuppressWarnings("deprecation")
            final boolean autoReconnect = connection.getConnectionOptions().autoReconnect();
            return processSync(connection, autoReconnect);
        }

        // Create the LDAP message.
        messageID = connection.nextMessageID();
        final LDAPMessage message = new LDAPMessage(messageID, this, getControls());

        // Register with the connection reader to be notified of responses for the
        // request that we've created.
        connection.registerResponseAcceptor(messageID, this);

        try {
            // Send the request to the server.
            final long responseTimeout = getResponseTimeoutMillis(connection);
            Debug.debugLDAPRequest(Level.INFO, this, messageID, connection);

            final long requestTime = System.nanoTime();
            connection.getConnectionStatistics().incrementNumBindRequests();
            connection.sendMessage(message, responseTimeout);

            // Wait for and process the response.
            LDAPResponse response = null;
            try {
                while (true) {
                    if (responseTimeout > 0) {
                        response = responseQueue.poll(responseTimeout, TimeUnit.MILLISECONDS);
                    } else {
                        response = responseQueue.take();
                    }

                    if (type3Message != null) {
                        break;
                    } else {
                        try {
                            BindResult result = (BindResult) response;
                            response = null;

                            ntlm.decodeType2Message(result.getResponseBytes());

                            type3Message = ntlm.createType3Message(username, password, null, domain);

                            messageID = connection.nextMessageID();
                            LDAPMessage message2 = new LDAPMessage(messageID, this, getControls());
                            connection.registerResponseAcceptor(messageID, this);
                            connection.sendMessage(message2, responseTimeout);

                        } catch (Exception e) {
                            e.printStackTrace();
                            break;
                        }

                    }
                }
            } catch (final InterruptedException ie) {
                Debug.debugException(ie);
                Thread.currentThread().interrupt();
                throw new LDAPException(ResultCode.LOCAL_ERROR,
                        ERR_BIND_INTERRUPTED.get(connection.getHostPort()), ie);
            }

            return handleResponse(connection, response, requestTime, false);
        } finally {
            connection.deregisterResponseAcceptor(messageID);
        }
    }

    @Override
    public void writeTo(ASN1Buffer buffer) {

        final ASN1BufferSequence requestSequence = buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST);
        buffer.addElement(VERSION_ELEMENT);

        if (type3Message == null) {
            buffer.addElement(new ASN1OctetString("NTLM"));

            ntlm = new NTLM();
            try {
                byte[] type1 = ntlm.createType1Message(null, null, 0xe20882b7);

                final ASN1OctetString pw = new ASN1OctetString((byte) 0x8a, type1);
                buffer.addElement(pw);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            buffer.addElement(new ASN1OctetString(""));
            final ASN1OctetString pw = new ASN1OctetString((byte) 0x8b, type3Message);
            buffer.addElement(pw);
        }
        requestSequence.end();
    }

    /**
     * {@inheritDoc}
     */
    @InternalUseOnly()
    @Override()
    public void responseReceived(@NotNull final LDAPResponse response)
            throws LDAPException {
        try {
            if (type3Message != null) {
                connection.getConnectionInternals(true).startNTLMSealing(ntlm.getMasterKey());
            }

            responseQueue.put(response);
        } catch (final Exception e) {
            Debug.debugException(e);

            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }

            throw new LDAPException(ResultCode.LOCAL_ERROR,
                    ERR_EXCEPTION_HANDLING_RESPONSE.get(
                            StaticUtils.getExceptionMessage(e)),
                    e);
        }
    }

}