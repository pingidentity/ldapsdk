/*
 * Copyright 2020-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2025 Ping Identity Corporation
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
 * Copyright (C) 2020-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.Base64;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides an implementation of an X.509 trust manager that can be
 * used to trust certificates listed in the topology registry of a Ping Identity
 * Directory Server instance.  It will read the topology registry from the
 * server's configuration file rather than communicating with it over LDAP, so
 * it is only available for use when run from LDAP tools provided with the
 * Ping Identity Directory Server.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TopologyRegistryTrustManager
       implements X509TrustManager, Serializable
{
  /**
   * The name of the object class that will be used in entries that may provide
   * information about inter-server certificates in the topology registry.
   */
  @NotNull private static final String INTER_SERVER_CERT_OC =
       "ds-cfg-server-instance";



  /**
   * The name of the attribute type for attributes that provide information
   * about inter-server certificates in the topology registry.
   */
  @NotNull private static final String INTER_SERVER_CERT_AT =
       "ds-cfg-inter-server-certificate";



  /**
   * The name of the object class that will be used in entries that may provide
   * information about listener certificates in the topology registry.
   */
  @NotNull private static final String LISTENER_CERT_OC =
       "ds-cfg-server-instance-listener";



  /**
   * The name of the attribute type for attributes that provide information
   * about listener certificates in the topology registry.
   */
  @NotNull private static final String LISTENER_CERT_AT =
       "ds-cfg-listener-certificate";



  /**
   * A pre-allocated empty certificate array.
   */
  @NotNull static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1535917071172094611L;



  // The time that the cached certificates will expire.
  @NotNull private final AtomicLong cacheExpirationTime;

  // The certificates that have been cached.
  @NotNull private final AtomicReference<Set<X509Certificate>>
       cachedCertificates;

  // Indicates whether to ignore the validity window for issuer certificates
  // when determining whether to trust a certificate chain.
  private final boolean ignoreIssuerCertificateValidityWindow;

  // Indicates whether to ignore the validity window for the peer certificate
  // when determining whether to trust a certificate chain.
  private final boolean ignorePeerCertificateValidityWindow;

  // Indicates whether to require the peer certificate itself to be included in
  // the topology registry for a certificate chain to be trusted.
  private final boolean requirePeerCertificateInTopologyRegistry;

  // The configuration file from which the certificate records will be read.
  @NotNull private final File configurationFile;

  // The maximum length of time in milliseconds that previously loaded
  // certificates may be cached.
  private final long cacheDurationMillis;



  /**
   * Creates a new instance of this trust manager with the provided settings.
   *
   * @param  configurationFile    The configuration file for the Ping Identity
   *                              Directory Server instance that holds the
   *                              topology registry data.  It must not be
   *                              {@code null}.
   * @param  cacheDurationMillis  The maximum length of time in milliseconds
   *                              that previously loaded certificates may be
   *                              cached.  If this is less than or equal to
   *                              zero, then certificates will not be cached.
   */
  public TopologyRegistryTrustManager(@NotNull final File configurationFile,
                                      final long cacheDurationMillis)
  {
    this(getDefaultProperties(configurationFile, cacheDurationMillis));
  }



  /**
   * Retrieves the topology registry trust manager properties that should be
   * used with the given configuration file and cache duration.
   *
   * @param  configurationFile    The configuration file for the Ping Identity
   *                              Directory Server instance that holds the
   *                              topology registry data.  It must not be
   *                              {@code null}.
   * @param  cacheDurationMillis  The maximum length of time in milliseconds
   *                              that previously loaded certificates may be
   *                              cached.  If this is less than or equal to
   *                              zero, then certificates will not be cached.
   *
   * @return  The topology registry trust manager configuration properties that
   *          should be used.
   */
  @NotNull()
  private static TopologyRegistryTrustManagerProperties getDefaultProperties(
               @NotNull final File configurationFile,
               final long cacheDurationMillis)
  {
    final TopologyRegistryTrustManagerProperties properties =
         new TopologyRegistryTrustManagerProperties(configurationFile);
    properties.setCacheDuration(cacheDurationMillis, TimeUnit.MILLISECONDS);
    return properties;
  }



  /**
   * Creates a new instance of this trust manager with the provided properties.
   *
   * @param  properties  The properties to use to create this trust manager.
   *                     It must not be {@code null}.
   */
  public TopologyRegistryTrustManager(
              @NotNull final TopologyRegistryTrustManagerProperties properties)
  {
    configurationFile = properties.getConfigurationFile();
    cacheDurationMillis = properties.getCacheDurationMillis();
    requirePeerCertificateInTopologyRegistry =
         properties.requirePeerCertificateInTopologyRegistry();
    ignorePeerCertificateValidityWindow =
         properties.ignorePeerCertificateValidityWindow();
    ignoreIssuerCertificateValidityWindow =
         properties.ignoreIssuerCertificateValidityWindow();

    cacheExpirationTime = new AtomicLong(0L);
    cachedCertificates = new AtomicReference<>(
         Collections.<X509Certificate>emptySet());
  }



  /**
   * Retrieves the server configuration file from which the topology registry
   * certificates will be read.
   *
   * @return  The server configuration file from which the topology registry
   *          certificates will be read.
   */
  @NotNull()
  public File getConfigurationFile()
  {
    return configurationFile;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that cached topology
   * registry information should be considered valid.
   *
   * @return  The maximum length of time in milliseconds that cached topology
   *          registry information should be considered valid, or zero if
   *          topology registry information should not be cached.
   */
  public long getCacheDurationMillis()
  {
    return cacheDurationMillis;
  }



  /**
   * Indicates whether to require the peer certificate itself to be included in
   * the topology registry for a certificate chain to be trusted.
   *
   * @return  {@code true} if a certificate chain may only be trusted if the
   *          topology registry includes the peer certificate itself, or
   *          {@code false} if a certificate chain may be trusted if the
   *          topology registry contains the peer certificate or any of its
   *          issuers.
   */
  public boolean requirePeerCertificateInTopologyRegistry()
  {
    return requirePeerCertificateInTopologyRegistry;
  }



  /**
   * Indicates whether to ignore the validity window for the peer certificate
   * when determining whether to trust a certificate chain.
   *
   * @return  {@code true} if a certificate chain may be considered trusted
   *          even if the current time is outside the peer certificate's
   *          validity window, or {@code false} if a certificate chain may only
   *          be considered trusted if the current time is between the
   *          {@code notBefore} and {@code notAfter} timestamps for the peer
   *          certificate.
   */
  public boolean ignorePeerCertificateValidityWindow()
  {
    return ignorePeerCertificateValidityWindow;
  }



  /**
   * Indicates whether to ignore the validity window for issuer certificates
   * when determining whether to trust a certificate chain.
   *
   * @return  {@code true} if a certificate chain may be considered trusted
   *          even if the current time is outside the any issuer certificate's
   *          validity window, or {@code false} if a certificate chain may only
   *          be considered trusted if the current time is between the
   *          {@code notBefore} and {@code notAfter} timestamps for all issuer
   *          certificates.
   */
  public boolean ignoreIssuerCertificateValidityWindow()
  {
    return ignoreIssuerCertificateValidityWindow;
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
    checkTrusted(chain);
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
    checkTrusted(chain);
  }



  /**
   * Ensures that the provided certificate chain should be trusted.
   *
   * @param  chain  The certificate chain to validated.
   *
   * @throws  CertificateException  If the certificate chain should not be
   *                                trusted.
   */
  private void checkTrusted(@NotNull final X509Certificate[] chain)
          throws CertificateException
  {
    // Make sure that the chain is not null or empty.
    if ((chain == null) || (chain.length == 0))
    {
      throw new CertificateException(ERR_TR_TM_NO_CHAIN.get());
    }


    // If appropriate, validate that the peer certificate is currently within
    // its validity window.
    final long currentTime = System.currentTimeMillis();
    final X509Certificate peerCert = chain[0];
    if (! ignorePeerCertificateValidityWindow)
    {
      if (currentTime < peerCert.getNotBefore().getTime())
      {
        throw new CertificateException(ERR_TR_TM_PEER_NOT_YET_VALID.get(
             peerCert.getSubjectX500Principal().getName(X500Principal.RFC2253),
             String.valueOf(peerCert.getNotBefore())));
      }

      if (currentTime > peerCert.getNotAfter().getTime())
      {
        throw new CertificateException(ERR_TR_TM_PEER_EXPIRED.get(
             peerCert.getSubjectX500Principal().getName(X500Principal.RFC2253),
             String.valueOf(peerCert.getNotAfter())));
      }
    }


    // If appropriate, validate that all of the issuer certificates are also
    // within their validity windows.
    if (! ignoreIssuerCertificateValidityWindow)
    {
      for (int i=1; i < chain.length; i++)
      {
        final X509Certificate issuerCert = chain[i];
        if (currentTime < issuerCert.getNotBefore().getTime())
        {
          throw new CertificateException(ERR_TR_TM_ISSUER_NOT_YET_VALID.get(
               peerCert.getSubjectX500Principal().getName(
                    X500Principal.RFC2253),
               issuerCert.getSubjectX500Principal().getName(
                    X500Principal.RFC2253),
               String.valueOf(peerCert.getNotBefore())));
        }

        if (currentTime > issuerCert.getNotAfter().getTime())
        {
          throw new CertificateException(ERR_TR_TM_ISSUER_EXPIRED.get(
               peerCert.getSubjectX500Principal().getName(
                    X500Principal.RFC2253),
               issuerCert.getSubjectX500Principal().getName(
                    X500Principal.RFC2253),
               String.valueOf(peerCert.getNotAfter())));
        }
      }
    }


    // If the cache is valid, then consult it to determine whether we should
    // trust the certificate chain.
    final Set<X509Certificate> cachedCerts = cachedCertificates.get();
    if ((! cachedCerts.isEmpty()) && (cacheExpirationTime.get() >= currentTime))
    {
      if (mayTrustChainBasedOnCertificateSet(chain, cachedCerts))
      {
        return;
      }
    }


    // If we've gotten here, then either caching is disabled, the cache is
    // expired, or the presented chain can't be trusted based on the cached
    // information.  In any case, read the configuration and extract all
    // certificates from the topology registry.
    final Set<X509Certificate> topologyRegistryCertificates =
         readTopologyRegistryCertificates();


    // If we should cache topology registry data, then update it with the set
    // of certificates we just read.
    if (cacheDurationMillis > 0L)
    {
      cachedCertificates.set(topologyRegistryCertificates);
      cacheExpirationTime.set(currentTime + cacheDurationMillis);
    }


    // Check to see if we should trust the certificate chain based on the
    // topology registry data we just read.
    if (mayTrustChainBasedOnCertificateSet(chain, topologyRegistryCertificates))
    {
      return;
    }


    // If we've gotten here, then the chain can't be considered trusted.
    if ((requirePeerCertificateInTopologyRegistry) || (chain.length == 1))
    {
      throw new CertificateException(ERR_TP_TM_PEER_NOT_FOUND.get(
           peerCert.getSubjectX500Principal().getName(X500Principal.RFC2253)));
    }
    else
    {
      throw new CertificateException(ERR_TP_TM_PEER_OR_ISSUERS_NOT_FOUND.get(
           peerCert.getSubjectX500Principal().getName(X500Principal.RFC2253)));
    }
  }



  /**
   * Indicates whether the provided certificate chain may be considered
   * trusted using the given set of trusted certificates.
   *
   * @param  chain           The certificate chain for which to make the
   *                         determination. It must not be {@code null} or
   *                         empty.
   * @param  certificateSet  The set of trusted certificates to use in making
   *                         the determination.  It must not be {@code null}.
   *
   * @return  {@code true} if the presented certificate chain may be considered
   *          trusted using the given set of trusted certificates, or
   *          {@code false} if not.
   */
  private boolean mayTrustChainBasedOnCertificateSet(
               @NotNull final X509Certificate[] chain,
               @NotNull final Set<X509Certificate> certificateSet)
  {
    // First, check the peer certificate.
    if (certificateSet.contains(chain[0]))
    {
      return true;
    }


    // If we don't require the peer certificate itself to be present in the
    // topology registry, then check its issuer certificates.
    if (! requirePeerCertificateInTopologyRegistry)
    {
      for (int i=1; i < chain.length; i++)
      {
        if (certificateSet.contains(chain[i]))
        {
          return true;
        }
      }
    }


    // If we've gotten here, then we can't trust the certificate chain based on
    // information in the provided set of trusted certificates.
    return false;
  }



  /**
   * Reads the certificates defined in the topology registry.
   *
   * @return  A set containing the certificates defined in the topology
   *          registry, or an empty set if no certificates are found.
   *
   * @throws  CertificateException  If a problem is encountered while reading
   *                                certificates from the topology registry.
   */
  @NotNull()
  private Set<X509Certificate> readTopologyRegistryCertificates()
          throws CertificateException
  {
    try (LDIFReader ldifReader = new LDIFReader(configurationFile))
    {
      final Set<X509Certificate> certs = new HashSet<>();
      while (true)
      {
        final Entry entry;
        try
        {
          entry = ldifReader.readEntry();
        }
        catch (final LDIFException e)
        {
          Debug.debugException(e);
          if (e.mayContinueReading())
          {
            continue;
          }
          else
          {
            throw new CertificateException(
                 ERR_TP_TM_MALFORMED_CONFIG.get(
                      configurationFile.getAbsolutePath(),
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
        }

        if (entry == null)
        {
          return Collections.unmodifiableSet(certs);
        }

        if (entry.hasObjectClass(INTER_SERVER_CERT_OC) &&
             entry.hasAttribute(INTER_SERVER_CERT_AT))
        {
          parseCertificates(certs, entry.getAttribute(INTER_SERVER_CERT_AT));
        }
        else if (entry.hasObjectClass(LISTENER_CERT_OC) &&
             entry.hasAttribute(LISTENER_CERT_AT))
        {
          parseCertificates(certs, entry.getAttribute(LISTENER_CERT_AT));
        }
      }
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      throw new CertificateException(
           ERR_TP_TM_ERROR_READING_CONFIG_FILE.get(
                configurationFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Parses any values of the provided attribute as a set of X.509 certificates.
   *
   * @param  certs  The set that should be updated with the certificates that
   *                are parsed.
   * @param  attr   The attribute whose values should be parsed.
   */
  private void parseCertificates(@NotNull final Set<X509Certificate> certs,
                                 @NotNull final Attribute attr)
  {
    final StringBuilder certBase64 = new StringBuilder();
    for (final String value : attr.getValues())
    {
      try
      {
        for (final String line : StaticUtils.stringToLines(value))
        {
          if (line.equalsIgnoreCase("-----BEGIN CERTIFICATE-----"))
          {
            continue;
          }
          else if (line.equalsIgnoreCase("-----END CERTIFICATE-----"))
          {
            final byte[] certBytes = Base64.decode(certBase64.toString());
            certBase64.setLength(0);

            certs.add((X509Certificate) CryptoHelper.getCertificateFactory(
                 "X.509").generateCertificate(new ByteArrayInputStream(
                      certBytes)));
          }
          else
          {
            certBase64.append(line);
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }



  /**
   * Retrieves the accepted issuer certificates for this trust manager.
   *
   * @return  The accepted issuer certificates for this trust manager, or an
   *          empty set of accepted issuers if a problem was encountered while
   *          initializing this trust manager.
   */
  @Override()
  @NotNull()
  public X509Certificate[] getAcceptedIssuers()
  {
    return NO_CERTIFICATES;
  }



  /**
   * Retrieves a string representation of this topology registry trust manager
   * instance.
   *
   * @return  A string representation of this topology registry trust manager
   *          instance.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this topology registry trust manager
   * instance to the given buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("TopologyRegistryTrustManager(configurationFile='");
    buffer.append(configurationFile.getAbsolutePath());
    buffer.append("', cacheDurationMillis=");
    buffer.append(cacheDurationMillis);
    buffer.append(", requirePeerCertificateInTopologyRegistry=");
    buffer.append(requirePeerCertificateInTopologyRegistry);
    buffer.append(", ignorePeerCertificateValidityWindow=");
    buffer.append(ignorePeerCertificateValidityWindow);
    buffer.append(", ignoreIssuerCertificateValidityWindow=");
    buffer.append(ignoreIssuerCertificateValidityWindow);
    buffer.append(')');
  }
}
