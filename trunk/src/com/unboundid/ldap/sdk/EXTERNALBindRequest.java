/*
 * Copyright 2007-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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



import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a SASL EXTERNAL bind request implementation as described
 * in <A HREF="http://www.ietf.org/rfc/rfc4422.txt">RFC 4422</A>.  The
 * EXTERNAL mechanism is used to authenticate using information that is
 * available outside of the LDAP layer (e.g., a certificate presented by the
 * client during SSL or StartTLS negotiation).
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing an EXTERNAL
 * bind against a directory server:
 * <PRE>
 *   try
 *   {
 *     BindResult bindResult = connection.bind(new EXTERNALBindRequest());
 *     // If we get here, then the bind was successful.
 *   }
 *   catch (LDAPException le)
 *   {
 *     // The bind failed for some reason.
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class EXTERNALBindRequest
       extends SASLBindRequest
{
  /**
   * The name for the EXTERNAL SASL mechanism.
   */
  public static final String EXTERNAL_MECHANISM_NAME = "EXTERNAL";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7520760039662616663L;



  // The message ID from the last LDAP message sent from this request.
  private int messageID = -1;



  /**
   * Creates a new SASL EXTERNAL bind request with no controls.
   */
  public EXTERNALBindRequest()
  {
    super(null);
  }




  /**
   * Creates a new SASL EXTERNAL bind request with the provided set of controls.
   *
   * @param  controls  The set of controls to include in this SASL EXTERNAL
   *                   bind request.
   */
  public EXTERNALBindRequest(final Control... controls)
  {
    super(controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSASLMechanismName()
  {
    return EXTERNAL_MECHANISM_NAME;
  }



  /**
   * Sends this bind request to the target server over the provided connection
   * and returns the corresponding response.
   *
   * @param  connection  The connection to use to send this bind request to the
   *                     server and read the associated response.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   *
   * @return  The bind response read from the server.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @Override()
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    return sendBindRequest(connection, "", null, getControls(),
                           getResponseTimeoutMillis(connection));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public EXTERNALBindRequest getRebindRequest(final String host, final int port)
  {
    return new EXTERNALBindRequest(getControls());
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
  public EXTERNALBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public EXTERNALBindRequest duplicate(final Control[] controls)
  {
    final EXTERNALBindRequest bindRequest = new EXTERNALBindRequest(controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("EXTERNALBindRequest(");

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
