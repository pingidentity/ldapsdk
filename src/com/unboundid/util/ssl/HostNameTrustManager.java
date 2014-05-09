/*
 * Copyright 2012-2013 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2013 UnboundID Corp.
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an SSL trust manager that will only accept certificates
 * whose hostname (as contained in the CN subject attribute or a subjectAltName
 * extension) matches an expected value.  Only the dNSName, iPAddress, and
 * uniformResourceIdentifier subjectAltName formats are supported.
 * <BR><BR>
 * This implementation optionally supports wildcard certificates, which have a
 * hostname that starts with an asterisk followed by a period and domain or
 * subdomain.  For example, "*.example.com" could be considered a match for
 * anything in the "example.com" domain.  If wildcards are allowed, then only
 * the CN subject attribute and dNSName subjectAltName extension will be
 * examined, and only the leftmost element of a hostname may be a wildcard
 * character.
 * <BR><BR>
 * Note that no other elements of the certificate are examined, so it is
 * strongly recommended that this trust manager be used in an
 * {@link AggregateTrustManager} in conjunction with other trust managers that
 * perform other forms of validation.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class HostNameTrustManager
       implements X509TrustManager
{
  /**
   * A pre-allocated empty certificate array.
   */
  private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];



  // Indicates whether to allow wildcard certificates (which
  private final boolean allowWildcards;

  // The set of hostname values that will be considered acceptable.
  private final Set<String> acceptableHostNames;



  /**
   * Creates a new hostname trust manager with the provided information.
   *
   * @param  allowWildcards       Indicates whether to allow wildcard
   *                              certificates which contain an asterisk as the
   *                              first component of a CN subject attribute or
   *                              dNSName subjectAltName extension.
   * @param  acceptableHostNames  The set of hostnames and/or IP addresses that
   *                              will be considered acceptable.  Only
   *                              certificates with a CN or subjectAltName value
   *                              that exactly matches one of these names
   *                              (ignoring differences in capitalization) will
   *                              be considered acceptable.  It must not be
   *                              {@code null} or empty.
   */
  public HostNameTrustManager(final boolean allowWildcards,
                              final String... acceptableHostNames)
  {
    this(allowWildcards, StaticUtils.toList(acceptableHostNames));
  }



  /**
   * Creates a new hostname trust manager with the provided information.
   *
   * @param  allowWildcards       Indicates whether to allow wildcard
   *                              certificates which contain an asterisk as the
   *                              first component of a CN subject attribute or
   *                              dNSName subjectAltName extension.
   * @param  acceptableHostNames  The set of hostnames and/or IP addresses that
   *                              will be considered acceptable.  Only
   *                              certificates with a CN or subjectAltName value
   *                              that exactly matches one of these names
   *                              (ignoring differences in capitalization) will
   *                              be considered acceptable.  It must not be
   *                              {@code null} or empty.
   */
  public HostNameTrustManager(final boolean allowWildcards,
                              final Collection<String> acceptableHostNames)
  {
    Validator.ensureNotNull(acceptableHostNames);
    Validator.ensureFalse(acceptableHostNames.isEmpty(),
         "The set of acceptable host names must not be empty.");

    this.allowWildcards = allowWildcards;

    final LinkedHashSet<String> nameSet =
         new LinkedHashSet<String>(acceptableHostNames.size());
    for (final String s : acceptableHostNames)
    {
      nameSet.add(StaticUtils.toLowerCase(s));
    }

    this.acceptableHostNames = Collections.unmodifiableSet(nameSet);
  }



  /**
   * Indicates whether wildcard certificates should be allowed, which may
   * match multiple hosts in a given domain or subdomain.
   *
   * @return  {@code true} if wildcard certificates should be allowed, or
   *          {@code false} if not.
   */
  public boolean allowWildcards()
  {
    return allowWildcards;
  }



  /**
   * Retrieves the set of hostnames that will be considered acceptable.
   *
   * @return  The set of hostnames that will be considered acceptable.
   */
  public Set<String> getAcceptableHostNames()
  {
    return acceptableHostNames;
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
  public void checkClientTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificate(chain[0]);
  }



  /**
   * Checks to determine whether the provided server certificate chain should be
   * trusted.
   *
   * @param  chain     The server certificate chain for which to make the
   *                   determination.
   * @param  authType  The key exchange algorithm used.
   *
   * @throws  CertificateException  If the provided server certificate chain
   *                                should not be trusted.
   */
  public void checkServerTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificate(chain[0]);
  }



  /**
   * Performs the appropriate validation for the given certificate.
   *
   * @param  c  The certificate to be validated.
   *
   * @throws  CertificateException  If the provided certificate does not have a
   *                                CN or subjectAltName value that matches one
   *                                of the acceptable hostnames.
   */
  private void checkCertificate(final X509Certificate c)
          throws CertificateException
  {
    // First, check the CN from the certificate subject.
    final String subjectDN =
         c.getSubjectX500Principal().getName(X500Principal.RFC2253);
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
            if (acceptableHostNames.contains(lowerValue))
            {
              return;
            }

            if (allowWildcards && lowerValue.startsWith("*."))
            {
              final String withoutWildcard = lowerValue.substring(1);
              for (final String s : acceptableHostNames)
              {
                if (s.endsWith(withoutWildcard))
                {
                  return;
                }
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
      debugException(e);
    }


    // Next, check any subjectAltName extension values.
    final Collection<List<?>> subjectAltNames = c.getSubjectAlternativeNames();
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
              final String dnsName = StaticUtils.toLowerCase((String) l.get(1));
              if (acceptableHostNames.contains(dnsName))
              {
                // We found a matching DNS host name.
                return;
              }

              // If the given DNS name starts with a "*.", then it's a wildcard
              // certificate.  See if that's allowed, and if so whether it
              // matches any acceptable name.
              if (allowWildcards && dnsName.startsWith("*."))
              {
                final String withoutWildcard = dnsName.substring(1);
                for (final String s : acceptableHostNames)
                {
                  if (s.endsWith(withoutWildcard))
                  {
                    return;
                  }
                }
              }
              break;

            case 6: // uniformResourceIdentifier
              final URI uri = new URI((String) l.get(1));
              if (acceptableHostNames.contains(
                   StaticUtils.toLowerCase(uri.getHost())))
              {
                // The URI had a matching address.
                return;
              }
              break;

            case 7: // iPAddress
              final InetAddress inetAddress =
                   InetAddress.getByName((String) l.get(1));
              for (final String s : acceptableHostNames)
              {
                if (Character.isDigit(s.charAt(0)) || (s.indexOf(':') >= 0))
                {
                  final InetAddress a = InetAddress.getByName(s);
                  if (inetAddress.equals(a))
                  {
                    return;
                  }
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
          debugException(e);
        }
      }
    }


    // If we've gotten here, then we didn't find a match.
    throw new CertificateException(ERR_HOSTNAME_NOT_FOUND.get(subjectDN));
  }



  /**
   * Retrieves the accepted issuer certificates for this trust manager.  This
   * will always return an empty array.
   *
   * @return  The accepted issuer certificates for this trust manager.
   */
  public X509Certificate[] getAcceptedIssuers()
  {
    return NO_CERTIFICATES;
  }
}
