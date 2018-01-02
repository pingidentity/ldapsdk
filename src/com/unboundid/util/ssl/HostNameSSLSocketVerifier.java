/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2018 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import java.net.InetAddress;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an implementation of an {@code SSLSocket} verifier that
 * will verify that the presented server certificate includes the address to
 * which the client intended to establish a connection.  It will check the CN
 * attribute of the certificate subject, as well as certain subjectAltName
 * extensions, including dNSName, uniformResourceIdentifier, and iPAddress.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class HostNameSSLSocketVerifier
       extends SSLSocketVerifier
{
  // Indicates whether to allow wildcard certificates which contain an asterisk
  // as the first component of a CN subject attribute or dNSName subjectAltName
  // extension.
  private final boolean allowWildcards;



  /**
   * Creates a new instance of this {@code SSLSocket} verifier.
   *
   * @param  allowWildcards  Indicates whether to allow wildcard certificates
   *                         which contain an asterisk as the first component of
   *                         a CN subject attribute or dNSName subjectAltName
   *                         extension.
   */
  public HostNameSSLSocketVerifier(final boolean allowWildcards)
  {
    this.allowWildcards = allowWildcards;
  }



  /**
   * Verifies that the provided {@code SSLSocket} is acceptable and the
   * connection should be allowed to remain established.
   *
   * @param  host       The address to which the client intended the connection
   *                    to be established.
   * @param  port       The port to which the client intended the connection to
   *                    be established.
   * @param  sslSocket  The {@code SSLSocket} that should be verified.
   *
   * @throws  LDAPException  If a problem is identified that should prevent the
   *                         provided {@code SSLSocket} from remaining
   *                         established.
   */
  @Override()
  public void verifySSLSocket(final String host, final int port,
                              final SSLSocket sslSocket)
         throws LDAPException
  {
    try
    {
      // Get the certificates presented during negotiation.  The certificates
      // will be ordered so that the server certificate comes first.
      final SSLSession sslSession = sslSocket.getSession();
      if (sslSession == null)
      {
        throw new LDAPException(ResultCode.CONNECT_ERROR,
             ERR_HOST_NAME_SSL_SOCKET_VERIFIER_NO_SESSION.get(host, port));
      }

      final Certificate[] peerCertificates = sslSession.getPeerCertificates();
      if ((peerCertificates == null) || (peerCertificates.length == 0))
      {
        throw new LDAPException(ResultCode.CONNECT_ERROR,
             ERR_HOST_NAME_SSL_SOCKET_VERIFIER_NO_PEER_CERTS.get(host, port));
      }

      if (peerCertificates[0] instanceof X509Certificate)
      {
        final StringBuilder certInfo = new StringBuilder();
        if (! certificateIncludesHostname(host,
             (X509Certificate) peerCertificates[0], allowWildcards, certInfo))
        {
          throw new LDAPException(ResultCode.CONNECT_ERROR,
               ERR_HOST_NAME_SSL_SOCKET_VERIFIER_HOSTNAME_NOT_FOUND.get(host,
                    certInfo.toString()));
        }
      }
      else
      {
        throw new LDAPException(ResultCode.CONNECT_ERROR,
             ERR_HOST_NAME_SSL_SOCKET_VERIFIER_PEER_NOT_X509.get(host, port,
                  peerCertificates[0].getType()));
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_HOST_NAME_SSL_SOCKET_VERIFIER_EXCEPTION.get(host, port,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Determines whether the provided certificate contains the specified
   * hostname.
   *
   * @param  host            The address expected to be found in the provided
   *                         certificate.
   * @param  certificate     The peer certificate to be validated.
   * @param  allowWildcards  Indicates whether to allow wildcard certificates
   *                         which contain an asterisk as the first component of
   *                         a CN subject attribute or dNSName subjectAltName
   *                         extension.
   * @param  certInfo        A buffer into which information will be provided
   *                         about the provided certificate.
   *
   * @return  {@code true} if the expected hostname was found in the
   *          certificate, or {@code false} if not.
   */
  static boolean certificateIncludesHostname(final String host,
                                             final X509Certificate certificate,
                                             final boolean allowWildcards,
                                             final StringBuilder certInfo)
  {
    final String lowerHost = StaticUtils.toLowerCase(host);

    // First, check the CN from the certificate subject.
    final String subjectDN =
         certificate.getSubjectX500Principal().getName(X500Principal.RFC2253);
    certInfo.append("subject='");
    certInfo.append(subjectDN);
    certInfo.append('\'');

    try
    {
      final DN dn = new DN(subjectDN);
      for (final RDN rdn : dn.getRDNs())
      {
        final String[] names  = rdn.getAttributeNames();
        final String[] values = rdn.getAttributeValues();
        for (int i=0; i < names.length; i++)
        {
          final String lowerName = StaticUtils.toLowerCase(names[i]);
          if (lowerName.equals("cn") || lowerName.equals("commonname") ||
              lowerName.equals("2.5.4.3"))
          {
            final String lowerValue = StaticUtils.toLowerCase(values[i]);
            if (lowerHost.equals(lowerValue))
            {
              return true;
            }

            if (allowWildcards && lowerValue.startsWith("*."))
            {
              final String withoutWildcard = lowerValue.substring(1);
              if (lowerHost.endsWith(withoutWildcard))
              {
                return true;
              }
            }
          }
        }
      }
    }
    catch (final Exception e)
    {
      // This shouldn't happen for a well-formed certificate subject, but we
      // have to handle it anyway.
      Debug.debugException(e);
    }


    // Next, check any supported subjectAltName extension values.
    final Collection<List<?>> subjectAltNames;
    try
    {
      subjectAltNames = certificate.getSubjectAlternativeNames();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return false;
    }

    if (subjectAltNames != null)
    {
      for (final List<?> l : subjectAltNames)
      {
        try
        {
          final Integer type = (Integer) l.get(0);
          switch (type)
          {
            case 2: // dNSName
              final String dnsName = (String) l.get(1);
              certInfo.append(" dNSName='");
              certInfo.append(dnsName);
              certInfo.append('\'');

              final String lowerDNSName = StaticUtils.toLowerCase(dnsName);
              if (lowerHost.equals(lowerDNSName))
              {
                return true;
              }

              // If the given DNS name starts with a "*.", then it's a wildcard
              // certificate.  See if that's allowed, and if so whether it
              // matches any acceptable name.
              if (allowWildcards && lowerDNSName.startsWith("*."))
              {
                final String withoutWildcard = lowerDNSName.substring(1);
                if (lowerHost.endsWith(withoutWildcard))
                {
                  return true;
                }
              }
              break;

            case 6: // uniformResourceIdentifier
              final String uriString = (String) l.get(1);
              certInfo.append(" uniformResourceIdentifier='");
              certInfo.append(uriString);
              certInfo.append('\'');

              final URI uri = new URI(uriString);
              if (lowerHost.equals(StaticUtils.toLowerCase(uri.getHost())))
              {
                return true;
              }
              break;

            case 7: // iPAddress
              final String ipAddressString = (String) l.get(1);
              certInfo.append(" iPAddress='");
              certInfo.append(ipAddressString);
              certInfo.append('\'');

              final InetAddress inetAddress =
                   InetAddress.getByName(ipAddressString);
              if (Character.isDigit(host.charAt(0)) || (host.indexOf(':') >= 0))
              {
                final InetAddress a = InetAddress.getByName(host);
                if (inetAddress.equals(a))
                {
                  return true;
                }
              }
              break;

            case 0: // otherName
            case 1: // rfc822Name
            case 3: // x400Address
            case 4: // directoryName
            case 5: // ediPartyName
            case 8: // registeredID
            default:
              // We won't do any checking for any of these formats.
              break;
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    return false;
  }
}
