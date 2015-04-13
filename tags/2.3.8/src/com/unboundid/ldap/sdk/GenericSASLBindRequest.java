/*
 * Copyright 2011-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2014 UnboundID Corp.
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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a mechanism for performing SASL authentication in a
 * generic manner.  The caller is responsible for properly encoding the
 * credentials (if any) and interpreting the result.  Further, if the requested
 * SASL mechanism is one that requires multiple stages, then the caller is
 * responsible for all processing in each stage.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GenericSASLBindRequest
       extends SASLBindRequest
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7740968332104559230L;



  // The SASL credentials that should be used for the bind request.
  private final ASN1OctetString credentials;

  // The bind DN to use for the bind request.
  private final String bindDN;

  // The name of the SASL mechanism that should be used for the bind request.
  private final String mechanism;



  /**
   * Creates a new generic SASL bind request with the provided information.
   *
   * @param  bindDN       The bind DN that should be used for the request.  It
   *                      may be {@code null} if the target identity should be
   *                      derived from the credentials or some other source.
   * @param  mechanism    The name of the mechanism that should be used for the
   *                      SASL bind.  It must not be {@code null}.
   * @param  credentials  The credentials that should be used for the SASL bind.
   *                      It may be {@code null} if no credentials should be
   *                      used.
   * @param  controls     The set of controls to include in the SASL bind
   *                      request.  It may be {@code null} or empty if no
   *                      request controls are needed.
   */
  public GenericSASLBindRequest(final String bindDN, final String mechanism,
                                final ASN1OctetString credentials,
                                final Control... controls)
  {
    super(controls);

    Validator.ensureNotNull(mechanism);

    this.bindDN      = bindDN;
    this.mechanism   = mechanism;
    this.credentials = credentials;
  }



  /**
   * Retrieves the bind DN for this SASL bind request, if any.
   *
   * @return  The bind DN for this SASL bind request, or {@code null} if the
   *          target identity should be determined from the credentials or some
   *          other mechanism.
   */
  public String getBindDN()
  {
    return bindDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSASLMechanismName()
  {
    return mechanism;
  }



  /**
   * Retrieves the credentials for the SASL bind request, if any.
   *
   * @return  The credentials for the SASL bind request, or {@code null} if
   *          there are none.
   */
  public ASN1OctetString getCredentials()
  {
    return credentials;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected BindResult process(final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    return sendBindRequest(connection, bindDN, credentials, getControls(),
         getResponseTimeoutMillis(connection));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public GenericSASLBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public GenericSASLBindRequest duplicate(final Control[] controls)
  {
    return new GenericSASLBindRequest(bindDN, mechanism, credentials,
         controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("GenericSASLBindRequest(mechanism='");
    buffer.append(mechanism);
    buffer.append('\'');

    if (bindDN != null)
    {
      buffer.append(", bindDN='");
      buffer.append(bindDN);
      buffer.append('\'');
    }

    if (credentials != null)
    {
      buffer.append(", credentials=byte[");
      buffer.append(credentials.getValueLength());
      buffer.append(']');
    }

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
