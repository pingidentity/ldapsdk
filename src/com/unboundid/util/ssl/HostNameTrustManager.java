/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.net.ssl.X509TrustManager;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

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
  @NotNull private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];



  // Indicates whether to allow wildcard certificates (which
  private final boolean allowWildcards;

  // Indicates whether to check the CN attribute in the peer certificate's
  // subject DN if the certificate also contains a subject alternative name
  // extension that contains at least dNSName, uniformResourceIdentifier, or
  // iPAddress value.
  private final boolean checkCNWhenSubjectAltNameIsPresent;

  // The set of hostname values that will be considered acceptable.
  @NotNull private final Set<String> acceptableHostNames;



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
                              @NotNull final String... acceptableHostNames)
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
              @NotNull final Collection<String> acceptableHostNames)
  {
    this(allowWildcards,
         HostNameSSLSocketVerifier.
              DEFAULT_CHECK_CN_WHEN_SUBJECT_ALT_NAME_IS_PRESENT,
         acceptableHostNames);
  }



  /**
   * Creates a new hostname trust manager with the provided information.
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
   * @param  acceptableHostNames
   *              The set of hostnames and/or IP addresses that will be
   *              considered acceptable.  Only certificates with a CN or
   *              subjectAltName value that exactly matches one of these names
   *              (ignoring differences in capitalization) will be considered
   *              acceptable.  It must not be {@code null} or empty.
   */
  public HostNameTrustManager(final boolean allowWildcards,
              final boolean checkCNWhenSubjectAltNameIsPresent,
              @NotNull final Collection<String> acceptableHostNames)
  {
    Validator.ensureNotNull(acceptableHostNames);
    Validator.ensureFalse(acceptableHostNames.isEmpty(),
         "The set of acceptable host names must not be empty.");

    this.allowWildcards = allowWildcards;
    this.checkCNWhenSubjectAltNameIsPresent =
         checkCNWhenSubjectAltNameIsPresent;

    final LinkedHashSet<String> nameSet = new LinkedHashSet<>(
         StaticUtils.computeMapCapacity(acceptableHostNames.size()));
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
  @NotNull()
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
  @Override()
  public void checkClientTrusted(@NotNull final X509Certificate[] chain,
                                 @NotNull final String authType)
         throws CertificateException
  {
    final StringBuilder buffer = new StringBuilder();
    for (final String s : acceptableHostNames)
    {
      buffer.setLength(0);
      if (HostNameSSLSocketVerifier.certificateIncludesHostname(s, chain[0],
           allowWildcards, checkCNWhenSubjectAltNameIsPresent, buffer))
      {
        return;
      }
    }

    throw new CertificateException(
         ERR_HOSTNAME_NOT_FOUND.get(buffer.toString()));
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
  @Override()
  public void checkServerTrusted(@NotNull final X509Certificate[] chain,
                                 @NotNull final String authType)
         throws CertificateException
  {
    final StringBuilder buffer = new StringBuilder();
    for (final String s : acceptableHostNames)
    {
      buffer.setLength(0);
      if (HostNameSSLSocketVerifier.certificateIncludesHostname(s, chain[0],
           allowWildcards, checkCNWhenSubjectAltNameIsPresent, buffer))
      {
        return;
      }
    }

    throw new CertificateException(
         ERR_HOSTNAME_NOT_FOUND.get(buffer.toString()));
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
