/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.LinkedBlockingQueue;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509TrustManager;

import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.tools.ResultUtils;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.SSLUtil;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides a thread that can be used to establish a connection to a
 * server, optionally use the LDAP StartTLS operation to initiate secure
 * communication over a previously-non-secure connection, and then capture the
 * certificate chain that the server presented to the client during TLS
 * negotiation.  That certificate chain, or any error encountered while trying
 * to obtain it, will be made available to the creator of this thread through a
 * queue.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class ManageCertificatesServerCertificateCollector
      extends Thread
      implements X509TrustManager
{
  /**
   * The column at which to wrap long lines of output.
   */
  private static final int WRAP_COLUMN =
       StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * A pre-allocated empty certificate array.
   */
  @NotNull private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];



  // Indicates whether the certificate chain has been retrieved from the server.
  private volatile boolean gotCertificateChain;

  // Indicates whether to use the LDAP StartTLS operation to trigger TLS
  // negotiation.
  private final boolean useLDAPStartTLS;

  // Indicates whether to operate in verbose mode.
  private final boolean verbose;

  // The port of the server to which the connection will be established.
  private final int port;

  // The queue that will be used to transfer the server certificate chain to the
  // caller.
  @NotNull private final LinkedBlockingQueue<Object> queue;

  // The associated manage-certificates tool instance.
  @NotNull private final ManageCertificates manageCertificates;

  // The address of the server to which the connection will be established.
  @NotNull private final String hostname;



  /**
   * Creates a new instance of this trust manager that will transfer the
   * presented server certificate chain to the given queue.
   *
   * @param  manageCertificates
   *              The associated manage-certificates tool instance.
   * @param  hostname
   *              The address of the server to which the connection will be
   *              established.
   * @param  port
   *              The port of the server to which the connection will be
   *              established.
   * @param  useLDAPStartTLS
   *              Indicates whether to use the LDAP StartTLS extended operation
   *              on the connection to trigger TLS negotiation.
   * @param  verbose
   *              Indicates whether to operate in verbose mode.
   * @param  queue
   *              The queue that will be used to transfer the server certificate
   *              chain to the caller.  Under normal conditions, the object
   *              placed on this queue will be a
   *              {@link com.unboundid.util.ssl.cert.X509Certificate}[].
   *              However, if an error is encountered during processing, then a
   *              {@link CertException} may be placed on the queue instead.
   */
  ManageCertificatesServerCertificateCollector(
       @NotNull final ManageCertificates manageCertificates,
       @NotNull final String hostname, final int port,
       final boolean useLDAPStartTLS, final boolean verbose,
       @NotNull final LinkedBlockingQueue<Object> queue)
  {
    setName("ManageCertificatesServerCertificateCollector background thread " +
         "for " + hostname + ':' + port);
    setDaemon(true);

    this.manageCertificates = manageCertificates;
    this.hostname = hostname;
    this.port = port;
    this.useLDAPStartTLS = useLDAPStartTLS;
    this.verbose = verbose;
    this.queue = queue;

    gotCertificateChain = false;
  }



  /**
   * Performs the core processing for this thread.  It will establish a TCP
   * connection to the specified server, optionally perform the LDAP StartTLS
   * operation, and initiate TLS negotiation so that the server's certificate
   * chain can be
   */
  @Override()
  public void run()
  {
    // Establish a non-secure connection to the target server.
    final String hostPort = hostname + ':' + port;
    if (verbose)
    {
      manageCertificates.wrapOut(0, WRAP_COLUMN,
           INFO_MANAGE_CERTS_CERT_COLLECTOR_CONNECTING.get(hostPort));
    }

    final Socket nonSecureSocket;
    try
    {
      nonSecureSocket = new Socket();

      final InetAddress address =
           LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.getByName(hostname);
      nonSecureSocket.connect(new InetSocketAddress(address, port), 60_000);
      if (verbose)
      {
        manageCertificates.wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_CERT_COLLECTOR_CONNECTED.get());
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      final String message =
           ERR_MANAGE_CERTS_CERT_COLLECTOR_CONNECT_FAILED.get(hostPort);
      manageCertificates.err();
      manageCertificates.wrapErr(0, WRAP_COLUMN, message);
      e.printStackTrace(manageCertificates.getErr());
      queue.offer(new CertException(message, e));
      return;
    }

    try
    {
      // If we should send an LDAP StartTLS extended request, then do that now.
      if (useLDAPStartTLS)
      {
        if (verbose)
        {
          manageCertificates.out();
          manageCertificates.wrapOut(0, WRAP_COLUMN,
               INFO_MANAGE_CERTS_CERT_COLLECTOR_SENDING_START_TLS.get());
        }

        final LDAPMessage startTLSRequestMessage = new LDAPMessage(1,
             new ExtendedRequestProtocolOp(
                  StartTLSExtendedRequest.STARTTLS_REQUEST_OID, null));
        try
        {
          nonSecureSocket.getOutputStream().write(
               startTLSRequestMessage.encode().encode());
          nonSecureSocket.getOutputStream().flush();

          final ASN1StreamReader asn1Reader = new ASN1StreamReader(
               nonSecureSocket.getInputStream());
          final LDAPMessage startTLSResponseMessage =
               LDAPMessage.readFrom(asn1Reader, true);

          if (startTLSResponseMessage == null)
          {
            // This could happen if the server terminated the connection for
            // some reason (e.g., it's not an LDAP server, or the user specified
            // an already-secure port).
            final String message =
                 ERR_MANAGE_CERTS_CERT_COLLECTOR_START_TLS_FAILED.get();
            manageCertificates.wrapErr(0, WRAP_COLUMN, message);
            queue.offer(new CertException(message));
            return;
          }

          final ExtendedResponseProtocolOp startTLSResponse =
               startTLSResponseMessage.getExtendedResponseProtocolOp();
          if (startTLSResponse.getResultCode() == ResultCode.SUCCESS_INT_VALUE)
          {
            if (verbose)
            {
              manageCertificates.wrapOut(0, WRAP_COLUMN,
                   INFO_MANAGE_CERTS_CERT_COLLECTOR_START_TLS_SUCCESSFUL.get());
            }
          }
          else
          {
            final String message =
                 ERR_MANAGE_CERTS_CERT_COLLECTOR_START_TLS_FAILED.get();
            manageCertificates.wrapErr(0, WRAP_COLUMN, message);

            final String[] referralURLArray = startTLSResponse.
                 getReferralURLs().toArray(StaticUtils.NO_STRINGS);
            final Control[] responseControlArray =
                 startTLSResponseMessage.getControls().toArray(
                      StaticUtils.NO_CONTROLS);

            final ExtendedResult extendedResult = new ExtendedResult(
                 startTLSRequestMessage.getMessageID(),
                 ResultCode.valueOf(startTLSResponse.getResultCode()),
                 startTLSResponse.getDiagnosticMessage(),
                 startTLSResponse.getMatchedDN(), referralURLArray,
                 startTLSResponse.getResponseOID(),
                 startTLSResponse.getResponseValue(), responseControlArray);
            for (final String line :
                 ResultUtils.formatResult(extendedResult, false, 0,
                      WRAP_COLUMN))
            {
              manageCertificates.err(line);
            }

            queue.offer(new CertException(message));
            return;
          }
        }
        catch (final Exception e)
        {
          final String message =
               ERR_MANAGE_CERTS_CERT_COLLECTOR_START_TLS_FAILED.get();
          manageCertificates.wrapErr(0, WRAP_COLUMN, message);
          e.printStackTrace(manageCertificates.getErr());
          queue.offer(new CertException(message));
          return;
        }
      }


      // Convert the non-secure Socket to an SSLSocket and begin TLS
      // negotiation.
      final SSLSocket sslSocket;
      try
      {
        if (verbose)
        {
          manageCertificates.out();
          manageCertificates.wrapOut(0, WRAP_COLUMN,
               INFO_MANAGE_CERTS_CERT_COLLECTOR_BEGINNING_TLS_NEGOTIATION.
                    get());
        }

        final SSLUtil sslUtil = new SSLUtil(this);
        sslSocket = (SSLSocket) sslUtil.createSSLSocketFactory().createSocket(
             nonSecureSocket, hostname, port, true);
        sslSocket.startHandshake();
        sslSocket.setSoTimeout(1000);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        final String message =
             ERR_MANAGE_CERTS_CERT_COLLECTOR_ERROR_STARTING_TLS_NEGOTIATION.
                  get();
        manageCertificates.wrapErr(0, WRAP_COLUMN, message);
        e.printStackTrace(manageCertificates.getErr());
        queue.offer(new CertException(message, e));
        return;
      }

      try
      {
        final long stopWaitingTime = System.currentTimeMillis() + 60_000L;
        while ((System.currentTimeMillis() < stopWaitingTime) &&
               (! gotCertificateChain))
        {
          try
          {
            final int bytesRead = sslSocket.getInputStream().read();
            if ((bytesRead < 0) && gotCertificateChain)
            {
              // The checkServerTrusted method will have already added something
              // to the queue, so we don't need to add anything here.
              return;
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
        }


        if (! gotCertificateChain)
        {
          // If we have gotten here, then it should mean that we timed out
          // without having gotten the certificate chain.
          final String message =
               ERR_MANAGE_CERTS_CERT_COLLECTOR_NO_CERT_CHAIN_RECEIVED.get(
                    hostPort);
          manageCertificates.wrapErr(0, WRAP_COLUMN, message);
          queue.offer(new CertException(message));
          return;
        }


        if (verbose)
        {
          final SSLSession sslSession = sslSocket.getSession();
          final String negotiatedProtocol = sslSession.getProtocol();
          if (negotiatedProtocol != null)
          {
            manageCertificates.wrapOut(0, WRAP_COLUMN,
                 INFO_MANAGE_CERTS_CERT_COLLECTOR_NEGOTIATED_TLS_PROTOCOL.get(
                      negotiatedProtocol));
          }

          final String negotiatedCipherSuite = sslSession.getCipherSuite();
          if (negotiatedCipherSuite != null)
          {
            manageCertificates.wrapOut(0, WRAP_COLUMN,
                 INFO_MANAGE_CERTS_CERT_COLLECTOR_NEGOTIATED_TLS_SUITE.get(
                      negotiatedCipherSuite));
          }
        }
      }
      finally
      {
        try
        {
          sslSocket.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }
    finally
    {
      try
      {
        nonSecureSocket.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }



  /**
   * Checks to determine whether the provided client certificate chain should be
   * trusted.
   *
   * @param  chain     The client certificate chain for which to make the
   *                   determination.
   * @param  authType  The authentication type based on the client certificate.
   *
   * @throws  CertificateException  If the provided client certificate chain
   *                                should not be trusted.
   */
  @Override()
  public void checkClientTrusted(@NotNull final X509Certificate[] chain,
                                 @NotNull final String authType)
         throws CertificateException
  {
    // No implementation is required.  We only care about server certificates,
    // not client certificates.
  }



  /**
   * Checks to determine whether the provided server certificate chain should be
   * trusted.
   *
   * @param  chain     The server certificate chain for which to make the
   *                   determination.
   * @param  authType  The key exchange algorithm used.
   */
  @Override()
  public void checkServerTrusted(@NotNull final X509Certificate[] chain,
                                 @NotNull final String authType)
         throws CertificateException
  {
    try
    {
      final com.unboundid.util.ssl.cert.X509Certificate[] c =
           new com.unboundid.util.ssl.cert.X509Certificate[chain.length];
      for (int i=0; i < chain.length; i++)
      {
        c[i] = new com.unboundid.util.ssl.cert.X509Certificate(
             chain[i].getEncoded());
      }

      if (verbose)
      {
        manageCertificates.wrapOut(0, WRAP_COLUMN,
             INFO_MANAGE_CERTS_CERT_COLLECTOR_GOT_CERT_CHAIN.get());
      }
      queue.offer(c);
      gotCertificateChain = true;
    }
    catch (final CertException ce)
    {
      Debug.debugException(ce);

      final String message =
           ERR_MANAGE_CERTS_CERT_COLLECTOR_ERROR_PARSING_CERT_CHAIN.get(
                hostname + ':' + port) + ":   " + ce.getMessage();
      manageCertificates.wrapErr(0, WRAP_COLUMN, message);
      for (final X509Certificate c : chain)
      {
        manageCertificates.err(c);
      }

      queue.offer(new CertException(message, ce.getCause()));
      gotCertificateChain = true;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      final String message =
           ERR_MANAGE_CERTS_CERT_COLLECTOR_ERROR_PARSING_CERT_CHAIN.get(
                hostname + ':' + port);
      manageCertificates.wrapErr(0, WRAP_COLUMN, message);
      e.printStackTrace(manageCertificates.getErr());
      queue.offer(new CertException(message, e));
      gotCertificateChain = true;
    }
  }



  /**
   * Retrieves the accepted issuer certificates for this trust manager.  This
   * will always return an empty array.
   *
   * @return  The accepted issuer certificates for this trust manager.
   */
  @Override()
  @NotNull()
  public X509Certificate[] getAcceptedIssuers()
  {
    return NO_CERTIFICATES;
  }
}
