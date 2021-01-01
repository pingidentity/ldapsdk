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
package com.unboundid.ldap.sdk;



import java.util.ArrayList;
import javax.security.sasl.SaslClient;

import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a SASL UNBOUNDID-TEST bind request implementation that
 * is intended for testing.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class UNBOUNDIDTESTBindRequest
      extends SASLBindRequest
{
  /**
   * The name for the UNBOUNDID-TEST SASL mechanism.
   */
  public static final String UNBOUNDID_TEST_MECHANISM_NAME = "UNBOUNDID-TEST";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2722228300388642072L;



  // The password for this bind request.
  private final byte[] password;

  // The message ID from the last LDAP message sent from this request.
  private int messageID = -1;

  // The desired QoP for this bind request.
  private final SASLQualityOfProtection qop;

  // The DN for this bind request.
  private final String dn;



  /**
   * Creates a new SASL UNBOUNDID-TEST bind request with the provided
   * information.
   *
   * @param  dn        The DN to use for the bind.
   * @param  password  The password to use for the bind.
   * @param  qop       The QoP to use for the bind.
   * @param  controls  The controls to include in the bind request.
   */
  UNBOUNDIDTESTBindRequest(final String dn, final byte[] password,
                           final SASLQualityOfProtection qop,
                           final Control... controls)
  {
    super(controls);

    this.dn       = dn;
    this.password = password;
    this.qop      = qop;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSASLMechanismName()
  {
    return UNBOUNDID_TEST_MECHANISM_NAME;
  }



  /**
   * Retrieves the DN for this bind request.
   *
   * @return  The DN for this bind request.
   */
  String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the password for this bind request.
   *
   * @return  The password for this bind request.
   */
  byte[] getPassword()
  {
    return password;
  }



  /**
   * Retrieves the quality of protection for this bind request.
   *
   * @return  The quality of protection for this bind request.
   */
  SASLQualityOfProtection getQoP()
  {
    return qop;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    final SaslClient saslClient =
         new UNBOUNDIDTESTSASLClient(dn, password, qop);

    final ArrayList<String> unhandledCallbackMessages = new ArrayList<>(0);
    final SASLClientBindHandler bindHandler = new SASLClientBindHandler(this,
         connection, UNBOUNDID_TEST_MECHANISM_NAME, saslClient, getControls(),
         getResponseTimeoutMillis(connection), unhandledCallbackMessages);

    try
    {
      return bindHandler.processSASLBind();
    }
    finally
    {
      messageID = bindHandler.getMessageID();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public UNBOUNDIDTESTBindRequest getRebindRequest(final String host,
                                                   final int port)
  {
    return new UNBOUNDIDTESTBindRequest(dn, password, qop, getControls());
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
  public UNBOUNDIDTESTBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public UNBOUNDIDTESTBindRequest duplicate(final Control[] controls)
  {
    final UNBOUNDIDTESTBindRequest bindRequest =
         new UNBOUNDIDTESTBindRequest(dn, password, qop, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("UNBOUNDIDTESTBindRequest(dn='");
    buffer.append(dn);
    buffer.append("', qop='");
    buffer.append(qop.toString());
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
