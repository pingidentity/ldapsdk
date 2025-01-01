/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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



import java.io.File;
import java.io.Serializable;
import java.util.concurrent.TimeUnit;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines a number of configuration properties that may be used by
 * the {@link TopologyRegistryTrustManager}.
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
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class TopologyRegistryTrustManagerProperties
       implements Serializable
{
  /**
   * The default cache duration in milliseconds.
   */
  private static final long DEFAULT_CACHE_DURATION_MILLIS =
       TimeUnit.MINUTES.toMillis(5L);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4753111539481801666L;



  // Indicates whether to ignore the validity window for issuer certificates
  // when determining whether to trust a certificate chain.
  private boolean ignoreIssuerCertificateValidityWindow;

  // Indicates whether to ignore the validity window for the peer certificate
  // when determining whether to trust a certificate chain.
  private boolean ignorePeerCertificateValidityWindow;

  // Indicates whether to require the peer certificate itself to be included in
  // the topology registry for a certificate chain to be trusted.
  private boolean requirePeerCertificateInTopologyRegistry;

  // The server configuration file from which the topology registry certificates
  // will be read.
  @NotNull private File configurationFile;

  // The maximum length of time in milliseconds that previously loaded
  // certificates may be cached.
  private long cacheDurationMillis;



  /**
   * Creates a new topology registry trust manager properties object with the
   * specified configuration file and the default settings for all other
   * properties.  Default settings include:
   * <UL>
   *   <LI>cacheDurationMillis -- 300,000 (five minutes)</LI>
   *   <LI>requirePeerCertificateInTopologyRegistry -- false</LI>
   *   <LI>ignorePeerCertificateValidityWindow -- false</LI>
   *   <LI>ignoreIssuerCertificateValidityWindow -- false</LI>
   * </UL>
   *
   * @param  configurationFilePath  The path to the server configuration file
   *                                from which the topology registry
   *                                certificates will be read.  It must not be
   *                                {@code null}, and the file must exist.
   */
  public TopologyRegistryTrustManagerProperties(
              @NotNull final String configurationFilePath)
  {
    this(new File(configurationFilePath));
  }



  /**
   * Creates a new topology registry trust manager properties object with the
   * specified configuration file and the default settings for all other
   * properties.  Default settings include:
   * <UL>
   *   <LI>cacheDurationMillis -- 300,000 (five minutes)</LI>
   *   <LI>requirePeerCertificateInTopologyRegistry -- false</LI>
   *   <LI>ignorePeerCertificateValidityWindow -- false</LI>
   *   <LI>ignoreIssuerCertificateValidityWindow -- false</LI>
   * </UL>
   *
   * @param  configurationFile  The server configuration file from which the
   *                            topology registry certificates will be read.  It
   *                            must not be {@code null}, and the file must
   *                            exist.
   */
  public TopologyRegistryTrustManagerProperties(
              @NotNull final File configurationFile)
  {
    Validator.ensureNotNull(configurationFile,
         "TopologyRegistryTrustManagerProperties.configurationFile must not " +
              "be null.");

    this.configurationFile = configurationFile;

    cacheDurationMillis = DEFAULT_CACHE_DURATION_MILLIS;
    requirePeerCertificateInTopologyRegistry = false;
    ignorePeerCertificateValidityWindow = false;
    ignoreIssuerCertificateValidityWindow = false;
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
   * Specifies the server configuration file from which the topology registry
   * certificates will be read.
   *
   * @param  configurationFile  The server configuration file from which the
   *                            topology registry certificates will be read.  It
   *                            must not be {@code null}, and the file must
   *                            exist.
   */
  public void setConfigurationFile(@NotNull final File configurationFile)
  {
    Validator.ensureNotNull(configurationFile,
         "TopologyRegistryTrustManagerProperties.configurationFile must not " +
              "be null.");

    this.configurationFile = configurationFile;
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
   * Specifies the maximum length of time that cached topology registry
   * information should be considered valid.
   *
   * @param  cacheDurationValue     The cache duration value to use with the
   *                                given time unit.  If this is less than or
   *                                equal to zero, then topology registry
   *                                information will not be cached.
   * @param  cacheDurationTimeUnit  The time unit to use with the given value.
   *                                It must not be {@code null}.
   */
  public void setCacheDuration(final long cacheDurationValue,
                               @NotNull final TimeUnit cacheDurationTimeUnit)
  {
    Validator.ensureNotNullWithMessage(cacheDurationTimeUnit,
         "TopologyRegistryTrustManagerProperties.setCacheDuration." +
              "cacheDurationTimeUnit must not be null.");

    if (cacheDurationValue <= 0L)
    {
      cacheDurationMillis = 0L;
    }
    else
    {
      cacheDurationMillis = cacheDurationTimeUnit.toMillis(cacheDurationValue);
    }
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
   * Specifies whether to require the peer certificate itself to be included in
   * the topology registry for a certificate chain to be trusted.
   *
   * @param  requirePeerCertificateInTopologyRegistry
   *              Indicates whether to require the peer certificate itself to be
   *              included in the topology registry for a certificate chain to
   *              be trusted.  If this is {@code true}, then a certificate chain
   *              may be trusted only if the topology registry contains the
   *              peer certificate itself.  If this is {@code false}, then a
   *              certificate chain may be trusted if the topology registry
   *              contains the peer certificate or any of its issuers.
   */
  public void setRequirePeerCertificateInTopologyRegistry(
                   final boolean requirePeerCertificateInTopologyRegistry)
  {
    this.requirePeerCertificateInTopologyRegistry =
         requirePeerCertificateInTopologyRegistry;
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
   * Indicates whether to ignore the validity window for the peer certificate
   * when determining whether to trust a certificate chain.
   *
   * @param  ignorePeerCertificateValidityWindow
   *              Specifies whether to ignore the validity window for the peer
   *              certificate when determining whether to trust a certificate
   *              chain.  If this is {@code true}, then a certificate chain may
   *              be trusted even if the current time is outside the peer
   *              certificate's validity window.  If this is {@code false}, then
   *              a certificate chain may only be trusted if the current time is
   *              between the {@code notBefore} and {@code notAfter} timestamps
   *              for the peer certificate.
   */
  public void setIgnorePeerCertificateValidityWindow(
                   final boolean ignorePeerCertificateValidityWindow)
  {
    this.ignorePeerCertificateValidityWindow =
         ignorePeerCertificateValidityWindow;
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
   * Indicates whether to ignore the validity window for the issuer certificates
   * when determining whether to trust a certificate chain.
   *
   * @param  ignoreIssuerCertificateValidityWindow
   *              Specifies whether to ignore the validity window for issuer
   *              certificates when determining whether to trust a certificate
   *              chain.  If this is {@code true}, then a certificate chain may
   *              be trusted even if the current time is outside any issuer
   *              certificate's validity window.  If this is {@code false}, then
   *              a certificate chain may only be trusted if the current time is
   *              between the {@code notBefore} and {@code notAfter} timestamps
   *              for all issuer certificate.
   */
  public void setIgnoreIssuerCertificateValidityWindow(
                   final boolean ignoreIssuerCertificateValidityWindow)
  {
    this.ignoreIssuerCertificateValidityWindow =
         ignoreIssuerCertificateValidityWindow;
  }



  /**
   * Retrieves a string representation of the topology registry trust manager
   * properties.
   *
   * @return  A string representation of the topology registry trust manager
   *          properties.
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
   * Appends a string representation of the topology registry trust manager
   * properties to the given buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("TopologyRegistryTrustManagerProperties(configurationFile='");
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
