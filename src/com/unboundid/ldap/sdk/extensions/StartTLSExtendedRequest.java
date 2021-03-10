/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPExtendedOperationException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.SSLUtil;

import static com.unboundid.ldap.sdk.extensions.ExtOpMessages.*;



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
 * it will use the {@link SSLUtil} class in conjunction with the
 * {@link com.unboundid.util.ssl.TrustStoreTrustManager} class to ensure that
 * only certificates from trusted authorities will be accepted.
 * <PRE>
 * // Create an SSLContext that will be used to perform the cryptographic
 * // processing.
 * SSLUtil sslUtil = new SSLUtil(new TrustStoreTrustManager(trustStorePath));
 * SSLContext sslContext = sslUtil.createSSLContext();
 *
 *  // Create and process the extended request to secure a connection.
 * StartTLSExtendedRequest startTLSRequest =
 *      new StartTLSExtendedRequest(sslContext);
 * ExtendedResult startTLSResult;
 * try
 * {
 *   startTLSResult = connection.processExtendedOperation(startTLSRequest);
 *   // This doesn't necessarily mean that the operation was successful, since
 *   // some kinds of extended operations return non-success results under
 *   // normal conditions.
 * }
 * catch (LDAPException le)
 * {
 *   // For an extended operation, this generally means that a problem was
 *   // encountered while trying to send the request or read the result.
 *   startTLSResult = new ExtendedResult(le);
 * }
 *
 * // Make sure that we can use the connection to interact with the server.
 * RootDSE rootDSE = connection.getRootDSE();
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
  @NotNull public static final String STARTTLS_REQUEST_OID =
       "1.3.6.1.4.1.1466.20037";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3234194603452821233L;



  // The SSL socket factory used to perform the negotiation.
  @Nullable private final SSLSocketFactory sslSocketFactory;



  /**
   * Creates a new StartTLS extended request using a default SSL context.
   *
   * @throws  LDAPException  If a problem occurs while trying to initialize a
   *                         default SSL context.
   */
  public StartTLSExtendedRequest()
         throws LDAPException
  {
    this((SSLSocketFactory) null, null);
  }



  /**
   * Creates a new StartTLS extended request using a default SSL context.
   *
   * @param  controls  The set of controls to include in the request.
   *
   * @throws  LDAPException  If a problem occurs while trying to initialize a
   *                         default SSL context.
   */
  public StartTLSExtendedRequest(@Nullable final Control[] controls)
         throws LDAPException
  {
    this((SSLSocketFactory) null, controls);
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
  public StartTLSExtendedRequest(@Nullable final SSLContext sslContext)
         throws LDAPException
  {
    this(sslContext, null);
  }



  /**
   * Creates a new StartTLS extended request using the provided SSL socket
   * factory.
   *
   * @param  sslSocketFactory  The SSL socket factory to use to convert an
   *                           insecure connection into a secure connection.  It
   *                           may be {@code null} to indicate that a default
   *                           SSL socket factory should be used.
   *
   * @throws  LDAPException  If a problem occurs while trying to initialize a
   *                         default SSL socket factory.
   */
  public StartTLSExtendedRequest(
              @Nullable final SSLSocketFactory sslSocketFactory)
         throws LDAPException
  {
    this(sslSocketFactory, null);
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
  public StartTLSExtendedRequest(@Nullable final SSLContext sslContext,
                                 @Nullable final Control[] controls)
         throws LDAPException
  {
    super(STARTTLS_REQUEST_OID, controls);

    if (sslContext == null)
    {
      try
      {
        final SSLContext ctx =
             CryptoHelper.getSSLContext(SSLUtil.getDefaultSSLProtocol());
        ctx.init(null, null, null);
        sslSocketFactory = ctx.getSocketFactory();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_STARTTLS_REQUEST_CANNOT_CREATE_DEFAULT_CONTEXT.get(e), e);
      }
    }
    else
    {
      sslSocketFactory = sslContext.getSocketFactory();
    }
  }



  /**
   * Creates a new StartTLS extended request.
   *
   * @param  sslSocketFactory  The SSL socket factory to use to convert an
   *                           insecure connection into a secure connection.  It
   *                           may be {@code null} to indicate that a default
   *                           SSL socket factory should be used.
   * @param  controls          The set of controls to include in the request.
   *
   * @throws  LDAPException  If a problem occurs while trying to initialize a
   *                         default SSL context.
   */
  public StartTLSExtendedRequest(
              @Nullable final SSLSocketFactory sslSocketFactory,
              @Nullable final Control[] controls)
         throws LDAPException
  {
    super(STARTTLS_REQUEST_OID, controls);

    if (sslSocketFactory == null)
    {
      try
      {
        final SSLContext ctx =
             CryptoHelper.getSSLContext(SSLUtil.getDefaultSSLProtocol());
        ctx.init(null, null, null);
        this.sslSocketFactory = ctx.getSocketFactory();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_STARTTLS_REQUEST_CANNOT_CREATE_DEFAULT_CONTEXT.get(e), e);
      }
    }
    else
    {
      this.sslSocketFactory = sslSocketFactory;
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
  public StartTLSExtendedRequest(@NotNull final ExtendedRequest extendedRequest)
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
   * Sends this StartTLS request to the server and performs the necessary
   * client-side security processing if the operation is processed successfully.
   * That this method is guaranteed to throw an {@code LDAPException} if the
   * server returns a non-success result.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be zero for the initial request, and should only
   *                     be incremented when following referrals.
   *
   * @return The extended result received from the server if StartTLS processing
   *         was completed successfully.
   *
   * @throws  LDAPException  If the server returned a non-success result, or if
   *                         a problem was encountered while performing
   *                         client-side security processing.
   */
  @Override()
  @NotNull()
  public ExtendedResult process(@NotNull final LDAPConnection connection,
                                final int depth)
         throws LDAPException
  {
    // Set an SO_TIMEOUT on the connection if it's not operating in synchronous
    // mode to make it more responsive during the negotiation phase.
    InternalSDKHelper.setSoTimeout(connection, 50);

    final ExtendedResult result = super.process(connection, depth);
    if (result.getResultCode() == ResultCode.SUCCESS)
    {
      InternalSDKHelper.convertToTLS(connection, sslSocketFactory);
    }
    else
    {
      throw new LDAPExtendedOperationException(result);
    }

    return result;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartTLSExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartTLSExtendedRequest duplicate(@Nullable final Control[] controls)
  {
    try
    {
      final StartTLSExtendedRequest r =
           new StartTLSExtendedRequest(sslSocketFactory, controls);
      r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
      return r;
    }
    catch (final Exception e)
    {
      // This should never happen, since an exception should only be thrown if
      // there is no SSL context, but this instance already has a context.
      Debug.debugException(e);
      throw new RuntimeException(e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_START_TLS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
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
