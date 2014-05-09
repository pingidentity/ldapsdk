/*
 * Copyright 2007-2013 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2013 UnboundID Corp.
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
package com.unboundid.ldap.sdk.extensions;



import javax.net.ssl.SSLContext;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.SSLUtil;

import static com.unboundid.ldap.sdk.extensions.ExtOpMessages.*;
import static com.unboundid.util.Debug.*;



/**
 * This class provides an implementation of the LDAP StartTLS extended request
 * as defined in <A HREF="http://www.ietf.org/rfc/rfc4511.txt">RFC 4511</A>
 * section 4.14.  It may be used to establish a secure communication channel
 * over an otherwise unencrypted connection.
 * <BR><BR>
 * Note that when using the StartTLS extended operation, you should establish
 * a connection to the server's unencrypted LDAP port rather than its secure
 * port.  Then, you can use the StartTLS extended request in order to secure
 * that connection.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example attempts to use the StartTLS extended request in order
 * to secure communication on a previously insecure connection.  In this case,
 * it will use the {@link com.unboundid.util.ssl.SSLUtil} class in conjunction
 * with the {@link com.unboundid.util.ssl.TrustAllTrustManager} class to
 * simplify the process of performing the SSL negotiation by blindly trusting
 * whatever certificate the server might happen to present.  In real-world
 * applications, if stronger verification is required then it is recommended
 * that you use an {@link SSLContext} that is configured to perform an
 * appropriate level of validation.
 * <PRE>
 *   SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
 *   SSLContext sslContext = sslUtil.createSSLContext();
 *   ExtendedResult extendedResult = connection.processExtendedOperation(
 *        new StartTLSExtendedRequest(sslContext));
 *
 *   // NOTE:  The processExtendedOperation method will only throw an exception
 *   // if a problem occurs while trying to send the request or read the
 *   // response.  It will not throw an exception because of a non-success
 *   // response.
 *
 *   if (extendedResult.getResultCode() == ResultCode.SUCCESS)
 *   {
 *     System.out.println("Communication with the server is now secure.");
 *   }
 *   else
 *   {
 *     System.err.println("An error occurred while attempting to perform " +
 *          "StartTLS negotiation.  The connection can no longer be used.");
 *     connection.close();
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class StartTLSExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.1466.20037) for the StartTLS extended request.
   */
  public static final String STARTTLS_REQUEST_OID = "1.3.6.1.4.1.1466.20037";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3234194603452821233L;



  // The SSL context to use to perform the negotiation.
  private final SSLContext sslContext;



  /**
   * Creates a new StartTLS extended request using a default SSL context.
   *
   * @throws  LDAPException  If a problem occurs while trying to initialize a
   *                         default SSL context.
   */
  public StartTLSExtendedRequest()
         throws LDAPException
  {
    this(null, null);
  }



  /**
   * Creates a new StartTLS extended request using a default SSL context.
   *
   * @param  controls  The set of controls to include in the request.
   *
   * @throws  LDAPException  If a problem occurs while trying to initialize a
   *                         default SSL context.
   */
  public StartTLSExtendedRequest(final Control[] controls)
         throws LDAPException
  {
    this(null, controls);
  }



  /**
   * Creates a new StartTLS extended request using the provided SSL context.
   *
   * @param  sslContext  The SSL context to use to perform the negotiation.  It
   *                     may be {@code null} to indicate that a default SSL
   *                     context should be used.  If an SSL context is provided,
   *                     then it must already be initialized.
   *
   * @throws  LDAPException  If a problem occurs while trying to initialize a
   *                         default SSL context.
   */
  public StartTLSExtendedRequest(final SSLContext sslContext)
         throws LDAPException
  {
    this(sslContext, null);
  }



  /**
   * Creates a new StartTLS extended request.
   *
   * @param  sslContext  The SSL context to use to perform the negotiation.  It
   *                     may be {@code null} to indicate that a default SSL
   *                     context should be used.  If an SSL context is provided,
   *                     then it must already be initialized.
   * @param  controls    The set of controls to include in the request.
   *
   * @throws  LDAPException  If a problem occurs while trying to initialize a
   *                         default SSL context.
   */
  public StartTLSExtendedRequest(final SSLContext sslContext,
                                 final Control[] controls)
         throws LDAPException
  {
    super(STARTTLS_REQUEST_OID, controls);

    if (sslContext == null)
    {
      try
      {
        this.sslContext =
             SSLContext.getInstance(SSLUtil.getDefaultSSLProtocol());
        this.sslContext.init(null, null, null);
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_STARTTLS_REQUEST_CANNOT_CREATE_DEFAULT_CONTEXT.get(e), e);
      }
    }
    else
    {
      this.sslContext = sslContext;
    }
  }



  /**
   * Creates a new StartTLS extended request from the provided generic extended
   * request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          StartTLS extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public StartTLSExtendedRequest(final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    this(extendedRequest.getControls());

    if (extendedRequest.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_STARTTLS_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ExtendedResult process(final LDAPConnection connection,
                                final int depth)
         throws LDAPException
  {
    // Set an SO_TIMEOUT on the connection if it's not operating in synchronous
    // mode to make it more responsive during the negotiation phase.
    InternalSDKHelper.setSoTimeout(connection, 50);

    final ExtendedResult result = super.process(connection, depth);
    if (result.getResultCode() == ResultCode.SUCCESS)
    {
      InternalSDKHelper.convertToTLS(connection, sslContext);
    }

    return result;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public StartTLSExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public StartTLSExtendedRequest duplicate(final Control[] controls)
  {
    try
    {
      final StartTLSExtendedRequest r =
           new StartTLSExtendedRequest(sslContext, controls);
      r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
      return r;
    }
    catch (Exception e)
    {
      // This should never happen, since an exception should only be thrown if
      // there is no SSL context, but this instance already has a context.
      debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_START_TLS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("StartTLSExtendedRequest(");

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append("controls={");
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
