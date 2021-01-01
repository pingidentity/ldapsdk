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
package com.unboundid.util.ssl;



import java.net.InetAddress;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.IPAddressArgumentValueValidator;

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
       implements HostnameVerifier
{
  /**
   * The name of a system property that can be used to specify the default
   * behavior that the verifier should exhibit when checking certificates that
   * contain both a CN attribute in the subject DN and a subject alternative
   * name extension that contains one or more dNSName,
   * uniformResourceIdentifier, or iPAddress values. Although RFC 6125 section
   * 6.4.4 indicates that the CN attribute should not be checked in certificates
   * that have an appropriate subject alternative name extension, LDAP clients
   * historically treat both sources as equally valid.
   */
  @NotNull public static final String
       PROPERTY_CHECK_CN_WHEN_SUBJECT_ALT_NAME_IS_PRESENT =
            HostNameSSLSocketVerifier.class.getName() +
                 ".checkCNWhenSubjectAltNameIsPresent";



  /**
   * Indicates whether to check the CN attribute in the peer certificate's
   * subject DN when that certificate also contains a subject subject
   * alternative name extension.
   */
  static final boolean DEFAULT_CHECK_CN_WHEN_SUBJECT_ALT_NAME_IS_PRESENT;
  static
  {
    boolean checkCN = true;
    final String propValue = StaticUtils.getSystemProperty(
         PROPERTY_CHECK_CN_WHEN_SUBJECT_ALT_NAME_IS_PRESENT);
    if ((propValue != null) && propValue.equalsIgnoreCase("false"))
    {
      checkCN = false;
    }

    DEFAULT_CHECK_CN_WHEN_SUBJECT_ALT_NAME_IS_PRESENT = checkCN;
  }



  // Indicates whether to allow wildcard certificates which contain an asterisk
  // as the first component of a CN subject attribute or dNSName subjectAltName
  // extension.
  private final boolean allowWildcards;

  // Indicates whether to check the CN attribute in the peer certificate's
  // subject DN if the certificate also contains a subject alternative name
  // extension that contains at least dNSName, uniformResourceIdentifier, or
  // iPAddress value.
  private final boolean checkCNWhenSubjectAltNameIsPresent;



  /**
   * Creates a new instance of this {@code SSLSocket} verifier.
   *
   * @param  allowWildcards  Indicates whether to allow wildcard certificates
   *                         that contain an asterisk in the leftmost component
   *                         of a hostname in the dNSName or
   *                         uniformResourceIdentifier of the subject
   *                         alternative name extension, or in the CN attribute
   *                         of the subject DN.
   */
  public HostNameSSLSocketVerifier(final boolean allowWildcards)
  {
    this(allowWildcards, DEFAULT_CHECK_CN_WHEN_SUBJECT_ALT_NAME_IS_PRESENT);
  }



  /**
   * Creates a new instance of this {@code SSLSocket} verifier.
   *
   * @param  allowWildcards
   *              Indicates whether to allow wildcard certificates that contain
   *              an asterisk in the leftmost component of a hostname in the
   *              dNSName or uniformResourceIdentifier of the subject
   *              alternative name extension, or in the CN attribute of the
   *              subject DN.
   * @param  checkCNWhenSubjectAltNameIsPresent
   *              Indicates whether to check the CN attribute in the peer
   *              certificate's subject DN if the certificate also contains a
   *              subject alternative name extension that contains at least one
   *              dNSName, uniformResourceIdentifier, or iPAddress value.
   *              Although RFC 6125 section 6.4.4 indicates that the CN
   *              attribute should not be checked in certificates that have an
   *              appropriate subject alternative name extension, LDAP clients
   *              historically treat both sources as equally valid.
   */
  public HostNameSSLSocketVerifier(final boolean allowWildcards,
              final boolean checkCNWhenSubjectAltNameIsPresent)
  {
    this.allowWildcards = allowWildcards;
    this.checkCNWhenSubjectAltNameIsPresent =
         checkCNWhenSubjectAltNameIsPresent;
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
  public void verifySSLSocket(@NotNull final String host, final int port,
                              @NotNull final SSLSocket sslSocket)
         throws LDAPException
  {
    verifySSLSession(host, port, sslSocket.getSession());
  }



  /**
   * Verifies that the provided {@code SSLSession} is acceptable and the
   * connection should be allowed to remain established.
   *
   * @param  host        The address to which the client intended the connection
   *                     to be established.
   * @param  port        The port to which the client intended the connection to
   *                     be established.
   * @param  sslSession  The SSL session that was negotiated.
   *
   * @throws  LDAPException  If a problem is identified that should prevent the
   *                         provided {@code SSLSocket} from remaining
   *                         established.
   */
  private void verifySSLSession(@NotNull final String host, final int port,
                               @NotNull final SSLSession sslSession)
          throws LDAPException
  {
    try
    {
      // Get the certificates presented during negotiation.  The certificates
      // will be ordered so that the server certificate comes first.
      if (sslSession == null)
      {
        throw new LDAPException(ResultCode.CONNECT_ERROR,
             ERR_HOST_NAME_SSL_SOCKET_VERIFIER_NO_SESSION.get(host, port));
      }

      final Certificate[] peerCertificateChain =
           sslSession.getPeerCertificates();
      if ((peerCertificateChain == null) || (peerCertificateChain.length == 0))
      {
        throw new LDAPException(ResultCode.CONNECT_ERROR,
             ERR_HOST_NAME_SSL_SOCKET_VERIFIER_NO_PEER_CERTS.get(host, port));
      }

      if (peerCertificateChain[0] instanceof X509Certificate)
      {
        final StringBuilder certInfo = new StringBuilder();
        if (! certificateIncludesHostname(host,
             (X509Certificate) peerCertificateChain[0], allowWildcards,
             checkCNWhenSubjectAltNameIsPresent, certInfo))
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
                  peerCertificateChain[0].getType()));
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
   * @param  host
   *              The address expected to be found in the provided certificate.
   * @param  certificate
   *              The peer certificate to be validated.
   * @param  allowWildcards
   *              Indicates whether to allow wildcard certificates that contain
   *              an asterisk in the leftmost component of a hostname in the
   *              dNSName or uniformResourceIdentifier of the subject
   *              alternative name extension, or in the CN attribute of the
   *              subject DN.
   * @param  checkCNWhenSubjectAltNameIsPresent
   *              Indicates whether to check the CN attribute in the peer
   *              certificate's subject DN if the certificate also contains a
   *              subject alternative name extension that contains at least one
   *              dNSName, uniformResourceIdentifier, or iPAddress value.  RFC
   *              6125 section 6.4.4 indicates that the CN attribute should not
   *              be checked in certificates that have an appropriate subject
   *              alternative name extension, although some clients may expect
   *              CN matching anyway.
   * @param  certInfo
   *              A buffer into which information will be provided about the
   *              provided certificate.
   *
   * @return  {@code true} if the expected hostname was found in the
   *          certificate, or {@code false} if not.
   */
  static boolean certificateIncludesHostname(@NotNull final String host,
                      @NotNull final X509Certificate certificate,
                      final boolean allowWildcards,
                      final boolean checkCNWhenSubjectAltNameIsPresent,
                      @NotNull final StringBuilder certInfo)
  {
    // Check to see if the provided hostname is an IP address.
    InetAddress hostInetAddress = null;
    if (IPAddressArgumentValueValidator.isValidNumericIPAddress(host))
    {
      try
      {
        hostInetAddress =
             LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.getByName(host);

        // Loopback IP addresses (but not names like "localhost") should be
        // considered "potentially trustworthy" as per the W3C Secure Contexts
        // Candidate Recommendation at https://www.w3.org/TR/secure-contexts/.
        // That means that when connecting over a loopback, we can assume that
        // the connection is established to the server we intended, even if that
        // loopback IP address isn't in the certificate's subject alternative
        // name extension or the CN attribute of the subject DN.
        if (hostInetAddress.isLoopbackAddress())
        {
          return true;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }


    // Check to see if the certificate has a subject alternative name extension.
    // If so, then check its dNSName, uniformResourceLocator, and iPAddress
    // elements.
    boolean hasAuthoritativeSubjectAlternativeName = false;
    try
    {
      final Collection<List<?>> subjectAltNames;
      subjectAltNames = certificate.getSubjectAlternativeNames();
      if (subjectAltNames != null)
      {
        for (final List<?> l : subjectAltNames)
        {
          final Integer type = (Integer) l.get(0);
          switch (type)
          {
            case 2: // dNSName
              final String dnsName = (String) l.get(1);
              certInfo.append(" dNSName='");
              certInfo.append(dnsName);
              certInfo.append('\'');

              if (hostnameMatches(host, dnsName, allowWildcards))
              {
                return true;
              }

              hasAuthoritativeSubjectAlternativeName = true;
              break;

            case 6: // uniformResourceIdentifier
              final String uriString = (String) l.get(1);
              certInfo.append(" uniformResourceIdentifier='");
              certInfo.append(uriString);
              certInfo.append('\'');

              final String uriHost = getHostFromURI(uriString);
              if (uriHost != null)
              {
                if (IPAddressArgumentValueValidator.isValidNumericIPAddress(
                     uriHost))
                {
                  if ((hostInetAddress != null) &&
                       ipAddressMatches(hostInetAddress, uriHost))
                  {
                    return true;
                  }
                }
                else if (hostnameMatches(host, uriHost, allowWildcards))
                {
                  return true;
                }
              }

              hasAuthoritativeSubjectAlternativeName = true;
              break;

            case 7: // iPAddress
              final String ipAddressString = (String) l.get(1);
              certInfo.append(" iPAddress='");
              certInfo.append(ipAddressString);
              certInfo.append('\'');

              if ((hostInetAddress != null) &&
                   ipAddressMatches(hostInetAddress, ipAddressString))
              {
                return true;
              }

              hasAuthoritativeSubjectAlternativeName = true;
              break;
          }
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    // If we found an authoritative subject alternative name and we should not
    // check the subject DN to see if it contains a CN attribute, then indicate
    // that we didn't find a match.
    if (hasAuthoritativeSubjectAlternativeName &&
         (! checkCNWhenSubjectAltNameIsPresent))
    {
      return false;
    }


    // Look for any CN attributes in the certificate subject.
    final String subjectDNString =
         certificate.getSubjectX500Principal().getName(X500Principal.RFC2253);
    certInfo.append("subject='");
    certInfo.append(subjectDNString);
    certInfo.append('\'');

    try
    {
      final DN subjectDN = new DN(subjectDNString);
      for (final RDN rdn : subjectDN.getRDNs())
      {
        final String[] names  = rdn.getAttributeNames();
        final String[] values = rdn.getAttributeValues();
        for (int i=0; i < names.length; i++)
        {
          final String lowerName = StaticUtils.toLowerCase(names[i]);
          if (lowerName.equals("cn") || lowerName.equals("commonname") ||
              lowerName.equals("2.5.4.3"))

          {
            final String cnValue = values[i];
            if (IPAddressArgumentValueValidator.
                 isValidNumericIPAddress(cnValue))
            {
              if ((hostInetAddress != null) &&
                   ipAddressMatches(hostInetAddress, cnValue))
              {
                return true;
              }
            }
            else
            {
              if (hostnameMatches(host, cnValue, allowWildcards))
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


    // If we've gotten here, then we can't consider the hostname a match.
    return false;
  }



  /**
   * Determines whether the provided client hostname matches the given
   * hostname from the certificate.
   *
   * @param  clientHostname
   *              The hostname that the client used when establishing the
   *              connection.
   * @param  certificateHostname
   *              A hostname obtained from the certificate.
   * @param  allowWildcards
   *              Indicates whether to allow wildcard certificates that contain
   *              an asterisk in the leftmost component of a hostname in the
   *              dNSName or uniformResourceIdentifier of the subject
   *              alternative name extension, or in the CN attribute of the
   *              subject DN.
   *
   * @return  {@code true} if the client hostname is considered a match for the
   *          certificate hostname, or {@code false} if not.
   */
  private static boolean hostnameMatches(@NotNull final String clientHostname,
                              @NotNull final String certificateHostname,
                              final boolean allowWildcards)
  {
    // If the provided certificate hostname does not contain any asterisks,
    // then we just need to do a case-insensitive match.
    if (! certificateHostname.contains("*"))
    {
      return clientHostname.equalsIgnoreCase(certificateHostname);
    }


    // The certificate hostname contains at least one wildcard.  See if that's
    // allowed.
    if (! allowWildcards)
    {
      return false;
    }


    // Get the first component and the remainder for both the client and
    // certificate hostnames.  If the remainder doesn't match, then it's not a
    // match.
    final ObjectPair<String,String> clientFirstComponentAndRemainder =
         getFirstComponentAndRemainder(clientHostname);
    final ObjectPair<String,String> certificateFirstComponentAndRemainder =
         getFirstComponentAndRemainder(certificateHostname);
    if (! clientFirstComponentAndRemainder.getSecond().equalsIgnoreCase(
         certificateFirstComponentAndRemainder.getSecond()))
    {
      return false;
    }


    // If the first component of the certificate hostname is just an asterisk,
    // then we can consider it a match.
    final String certificateFirstComponent =
         certificateFirstComponentAndRemainder.getFirst();
    if (certificateFirstComponent.equals("*"))
    {
      return true;
    }


    // The filter has wildcard and non-wildcard components.  At this point, the
    // easiest thing to do is to try to create a substring filter to get the
    // individual components of the filter.
    final Filter filter;
    try
    {
      filter = Filter.create("(hostname=" + certificateFirstComponent + ')');
      if (filter.getFilterType() != Filter.FILTER_TYPE_SUBSTRING)
      {
        return false;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return false;
    }


    return CaseIgnoreStringMatchingRule.getInstance().matchesSubstring(
         new ASN1OctetString(clientFirstComponentAndRemainder.getFirst()),
         filter.getRawSubInitialValue(),
         filter.getRawSubAnyValues(), filter.getRawSubFinalValue());
  }



  /**
   * Separates the provided address into the leftmost component (everything up
   * to the first period) and the remainder (everything else, including the
   * first period).  If the provided address does not contain any periods, then
   * the leftmost component will be the entire value and the remainder will be
   * an empty string.
   *
   * @param  address  The address to be separated into the leftmost component
   *                  and the remainder.  It must not be {@code null}.
   *
   * @return  An object pair in which the first element is the leftmost
   *          component of the provided address and the second element is the
   *          remainder of the address.
   */
  @NotNull()
  private static ObjectPair<String,String> getFirstComponentAndRemainder(
                                                @NotNull final String address)
  {
    final int periodPos = address.indexOf('.');
    if (periodPos < 0)
    {
      return new ObjectPair<>(address, "");
    }
    else
    {
      return new ObjectPair<>(address.substring(0, periodPos),
           address.substring(periodPos));
    }
  }



  /**
   * Determines whether the provided client IP address matches the IP address
   * represented by the provided string.
   *
   * @param  clientIPAddress
   *              The IP address that the client used when establishing the
   *              connection.
   * @param  certificateIPAddressString
   *              The string representation of an IP address obtained from the
   *              certificate.
   *
   * @return  {@code true} if the client hostname is considered a match for the
   *          certificate hostname, or {@code false} if not.
   */
  private static boolean ipAddressMatches(
                              @NotNull final InetAddress clientIPAddress,
                              @NotNull final String certificateIPAddressString)
  {
    final InetAddress certificateIPAddress;
    try
    {
      certificateIPAddress = LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.
           getByName(certificateIPAddressString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return false;
    }

    return clientIPAddress.equals(certificateIPAddress);
  }



  /**
   * Extracts the host from the URI with the given string representation.  Note
   * that the Java URI parser doesn't like hostnames that have wildcards, so we
   * have to handle them specially.
   *
   * @param  uriString  The string representation of the URI to parse.  It must
   *                    not be {@code null}.
   *
   * @return  The host extracted from the provided URI, or {@code null} if none
   *          is available (e.g., because the URI is malformed).
   */
  @Nullable()
  private static String getHostFromURI(@NotNull final String uriString)
  {
    final URI uri;
    try
    {
      uri = new URI(uriString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }

    final String uriHost = uri.getHost();
    if (uriHost != null)
    {
      return uriHost;
    }


    // Java's URI code can't handle hosts with wildcards.  See if the provided
    // URI string looks like it might contain a wildcard.  If not, then just
    // return null.
    if (! uriString.contains("*"))
    {
      return null;
    }


    // If Java was at least able to parse the scheme, and if the URI starts with
    // that scheme, then we can go ahead with our own parsing attempt.
    final String scheme = uri.getScheme();
    if ((scheme == null) || scheme.isEmpty() ||
         (! uriString.toLowerCase().startsWith(scheme)))
    {
      return null;
    }


    // Strip the scheme from the beginning of the URI.  Note that the scheme
    // probably won't contain the "://", so strip that separately.
    String paredDownURI = uriString.substring(scheme.length());
    if (paredDownURI.startsWith("://"))
    {
      paredDownURI = paredDownURI.substring(3);
    }


    // If the pared down URI contains a slash (which would separate the hostport
    // section from the path), then strip that off and everything after it.
    final int slashPos = paredDownURI.indexOf('/');
    if (slashPos >= 0)
    {
      paredDownURI = paredDownURI.substring(0, slashPos);
    }


    // If the pared down URI contains a colon (which would separate the host
    // from the port), then strip that off and everything after it.
    final int colonPos = paredDownURI.indexOf(':');
    if (colonPos >= 0)
    {
      paredDownURI = paredDownURI.substring(0, colonPos);
    }


    // If there's anything left, then it should be the host.
    if (! paredDownURI.isEmpty())
    {
      return paredDownURI;
    }

    return null;
  }



  /**
   * Verifies that the provided hostname is acceptable for use with the
   * negotiated SSL session.
   *
   * @param  hostname  The address to which the client intended the connection
   *                   to be established.
   * @param  session   The SSL session that was established.
   */
  @Override()
  public boolean verify(@NotNull final String hostname,
                        @NotNull final SSLSession session)
  {
    try
    {
      verifySSLSession(hostname, session.getPeerPort(), session);
      return true;
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      return false;
    }
  }
}
