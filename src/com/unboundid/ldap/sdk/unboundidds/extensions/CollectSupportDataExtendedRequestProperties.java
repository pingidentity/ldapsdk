/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.io.Serializable;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.unboundidds.tasks.CollectSupportDataSecurityLevel;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines a set of properties that may be used when creating a
 * {@link CollectSupportDataExtendedRequest}.
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
public final class CollectSupportDataExtendedRequestProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5585016444537427389L;



  // The passphrase to use to encrypt the contents of the support data archive.
  @Nullable private ASN1OctetString encryptionPassphrase;

  // Indicates whether to include binary files in the support data archive.
  @Nullable private Boolean includeBinaryFiles;

  // Indicates whether to include expensive data in the support data archive.
  @Nullable private Boolean includeExpensiveData;

  // Indicates whether to include third-party extension source code in the
  // support data archive.
  @Nullable private Boolean includeExtensionSource;

  // Indicates whether to include a replication state dump in the support data
  // archive.
  @Nullable private Boolean includeReplicationStateDump;

  // Indicates whether to capture information sequentially rather than in
  // parallel.
  @Nullable private Boolean useSequentialMode;

  // The log capture window that indicates how much log content to include in
  // the support data archive.
  @Nullable private CollectSupportDataLogCaptureWindow logCaptureWindow;

  // The security level to use for data included in the support data archive.
  @Nullable private CollectSupportDataSecurityLevel securityLevel;

  // The number of jstacks to include in the support data archive.
  @Nullable private Integer jstackCount;

  // The maximum size, in bytes, of any support data archive fragment to include
  // in a collect support data archive fragment intermediate response.
  @Nullable private Integer maximumFragmentSizeBytes;

  // The port of a backend Directory Server instance to which the collect
  // support data extended request should be forwarded.
  @Nullable private Integer proxyToServerPort;

  // The report count to use for sampled metrics.
  @Nullable private Integer reportCount;

  // The report interval in seconds to use for sampled metrics.
  @Nullable private Integer reportIntervalSeconds;

  // The name (without any path information) the client intends to use for the
  // support data archive file.
  @Nullable private String archiveFileName;

  // A comment to include in the support data archive.
  @Nullable private String comment;

  // The address of a backend Directory Server to which the collect support data
  // extended request should be forwarded.
  @Nullable private String proxyToServerAddress;



  /**
   * Creates a new set of collect support data extended request properties
   * with none of the properties set, indicating that the server should use the
   * default values for all of them.
   */
  public CollectSupportDataExtendedRequestProperties()
  {
    encryptionPassphrase = null;
    includeBinaryFiles = null;
    includeExpensiveData = null;
    includeExtensionSource = null;
    includeReplicationStateDump = null;
    useSequentialMode = null;
    logCaptureWindow = null;
    securityLevel = null;
    jstackCount = null;
    maximumFragmentSizeBytes = null;
    proxyToServerPort = null;
    reportCount = null;
    reportIntervalSeconds = null;
    archiveFileName = null;
    comment = null;
    proxyToServerAddress = null;
  }



  /**
   * Creates a new set of collect support data extended request properties
   * that is a copy of the provided properties.
   *
   * @param  properties  The set of properties to duplicate.
   */
  public CollectSupportDataExtendedRequestProperties(
       @NotNull final CollectSupportDataExtendedRequestProperties properties)
  {
    encryptionPassphrase = properties.getEncryptionPassphrase();
    includeBinaryFiles = properties.getIncludeBinaryFiles();
    includeExpensiveData = properties.getIncludeExpensiveData();
    includeExtensionSource = properties.getIncludeExtensionSource();
    includeReplicationStateDump = properties.getIncludeReplicationStateDump();
    useSequentialMode = properties.getUseSequentialMode();
    logCaptureWindow = properties.getLogCaptureWindow();
    securityLevel = properties.getSecurityLevel();
    jstackCount = properties.getJStackCount();
    maximumFragmentSizeBytes = properties.getMaximumFragmentSizeBytes();
    proxyToServerPort = properties.getProxyToServerPort();
    reportCount = properties.getReportCount();
    reportIntervalSeconds = properties.getReportIntervalSeconds();
    archiveFileName = properties.getArchiveFileName();
    comment = properties.getComment();
    proxyToServerAddress = properties.getProxyToServerAddress();
  }



  /**
   * Creates a new set of collect support data extended request properties
   * using the settings from the provided extended request.
   *
   * @param  request  The collect support data extended request from which to
   *                  set the property values.
   */
  public CollectSupportDataExtendedRequestProperties(
       @NotNull final CollectSupportDataExtendedRequest request)
  {
    encryptionPassphrase = request.getEncryptionPassphrase();
    includeBinaryFiles = request.getIncludeBinaryFiles();
    includeExpensiveData = request.getIncludeExpensiveData();
    includeExtensionSource = request.getIncludeExtensionSource();
    includeReplicationStateDump = request.getIncludeReplicationStateDump();
    useSequentialMode = request.getUseSequentialMode();
    logCaptureWindow = request.getLogCaptureWindow();
    securityLevel = request.getSecurityLevel();
    jstackCount = request.getJStackCount();
    maximumFragmentSizeBytes = request.getMaximumFragmentSizeBytes();
    proxyToServerPort = request.getProxyToServerPort();
    reportCount = request.getReportCount();
    reportIntervalSeconds = request.getReportIntervalSeconds();
    archiveFileName = request.getArchiveFileName();
    comment = request.getComment();
    proxyToServerAddress = request.getProxyToServerAddress();
  }



  /**
   * Retrieves the name (without any path information) that the client intends
   * to use for the support data archive file.
   *
   * @return  The name (without any path information) that the client intends to
   *          use for the support data archive file, or {@code null} if the
   *          server should generate an archive file name.
   */
  @Nullable()
  public String getArchiveFileName()
  {
    return archiveFileName;
  }



  /**
   * Specifies the name (without any path information) that the client intends
   * to use for the support data archive file.
   *
   * @param  archiveFileName  The name (without any path information) that the
   *                          client intends to use for the support data archive
   *                          file.  It may be {@code null} if the server
   *                          should generate an archive file name.
   */
  public void setArchiveFileName(@Nullable final String archiveFileName)
  {
    this.archiveFileName = archiveFileName;
  }



  /**
   * Retrieves the passphrase that should be used to encrypt the contents of the
   * support data archive.
   *
   * @return  The passphrase that should be used to encrypt the contents of the
   *          support data archive, or {@code null} if the archive should not
   *          be encrypted.
   */
  @Nullable()
  public ASN1OctetString getEncryptionPassphrase()
  {
    return encryptionPassphrase;
  }



  /**
   * Specifies the passphrase that should be used to encrypt the contents of the
   * support data archive.
   *
   * @param  encryptionPassphrase  The passphrase that should be used to
   *                               encrypt the contents of the support data
   *                               archive.  It may be {@code null} if the
   *                               support data archive should not be encrypted.
   */
  public void setEncryptionPassphrase(
                   @Nullable final String encryptionPassphrase)
  {
    if (encryptionPassphrase == null)
    {
      this.encryptionPassphrase = null;
    }
    else
    {
      this.encryptionPassphrase = new ASN1OctetString(
           CollectSupportDataExtendedRequest.TYPE_ENCRYPTION_PASSPHRASE,
           encryptionPassphrase);
    }
  }



  /**
   * Specifies the passphrase that should be used to encrypt the contents of the
   * support data archive.
   *
   * @param  encryptionPassphrase  The passphrase that should be used to
   *                               encrypt the contents of the support data
   *                               archive.  It may be {@code null} if the
   *                               support data archive should not be encrypted.
   */
  public void setEncryptionPassphrase(
                   @Nullable final byte[] encryptionPassphrase)
  {
    if (encryptionPassphrase == null)
    {
      this.encryptionPassphrase = null;
    }
    else
    {
      this.encryptionPassphrase = new ASN1OctetString(
           CollectSupportDataExtendedRequest.TYPE_ENCRYPTION_PASSPHRASE,
           encryptionPassphrase);
    }
  }



  /**
   * Specifies the passphrase that should be used to encrypt the contents of the
   * support data archive.
   *
   * @param  encryptionPassphrase  The passphrase that should be used to
   *                               encrypt the contents of the support data
   *                               archive.  It may be {@code null} if the
   *                               support data archive should not be encrypted.
   */
  public void setEncryptionPassphrase(
                   @Nullable final ASN1OctetString encryptionPassphrase)
  {
    if (encryptionPassphrase == null)
    {
      this.encryptionPassphrase = null;
    }
    else
    {
      this.encryptionPassphrase = new ASN1OctetString(
           CollectSupportDataExtendedRequest.TYPE_ENCRYPTION_PASSPHRASE,
           encryptionPassphrase.getValue());
    }
  }



  /**
   * Retrieves the value of a flag that indicates whether the support data
   * archive may include data that is potentially expensive to collect and
   * could affect the performance or responsiveness of the server.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive may include data that is potentially expensive to collect,
   *          or {@code null} if the property should not be specified when the
   *          request is created (in which case the server will use a default
   *          behavior of excluding expensive data).
   */
  @Nullable()
  public Boolean getIncludeExpensiveData()
  {
    return includeExpensiveData;
  }



  /**
   * Specifies the value of a flag that indicates whether the support data
   * archive may include data that is potentially expensive to collect and could
   * affect the performance or responsiveness of the server.
   *
   * @param  includeExpensiveData  The value of a flag that indicates whether
   *                               the support data archive may include data
   *                               that is potentially expensive to collect.  It
   *                               may be {@code null} if the flag should not be
   *                               specified when the request is created (in
   *                               which case the server will use a default
   *                               behavior of excluding expensive data).
   */
  public void setIncludeExpensiveData(
                   @Nullable final Boolean includeExpensiveData)
  {
    this.includeExpensiveData = includeExpensiveData;
  }



  /**
   * Retrieves the value of a flag that indicates whether the support data
   * archive may include a replication state dump, which may be several
   * megabytes in size.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive may include a replication state dump, or {@code null} if
   *          the property should not be specified when the request is created
   *          (in which case the server will use a default behavior of
   *          excluding the state dump).
   */
  @Nullable()
  public Boolean getIncludeReplicationStateDump()
  {
    return includeReplicationStateDump;
  }



  /**
   * Specifies the value of a flag that indicates whether the support data
   * archive may include a replication state dump, which may be several
   * megabytes in size.
   *
   * @param  includeReplicationStateDump  The value of a flag that indicates
   *                                      whether the support data archive may
   *                                      include a replication state dump.  It
   *                                      may be {@code null} if the flag should
   *                                      not be specified when the request is
   *                                      created (in which case the server will
   *                                      use a default behavior of excluding
   *                                      the state dump).
   */
  public void setIncludeReplicationStateDump(
                   @Nullable final Boolean includeReplicationStateDump)
  {
    this.includeReplicationStateDump = includeReplicationStateDump;
  }



  /**
   * Retrieves the value of a flag that indicates whether the support data
   * archive may include binary files.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive may include binary files, or {@code null} if the property
   *          should not be specified when the request is created (in which case
   *          the server will use a default behavior of excluding binary files).
   */
  @Nullable()
  public Boolean getIncludeBinaryFiles()
  {
    return includeBinaryFiles;
  }



  /**
   * Specifies the value of a flag that that indicates whether the support data
   * archive may include binary files.
   *
   * @param  includeBinaryFiles  The value of a flag that indicates whether the
   *                             support data archive may include binary files.
   *                             It may be {@code null} if the property should
   *                             not be specified when the request is created
   *                             (in which case the server will use a default
   *                             behavior of excluding binary files).
   */
  public void setIncludeBinaryFiles(@Nullable final Boolean includeBinaryFiles)
  {
    this.includeBinaryFiles = includeBinaryFiles;
  }



  /**
   * Retrieves the value of a flag that indicates whether the support data
   * archive should include source code (if available) for any third-party
   * extensions installed in the server.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive should include source code (if available) for any
   *          third-party extensions installed in the server, or {@code null} if
   *          the property should not be specified when the request is created
   *          (in which case the server will use a default behavior of excluding
   *          extension source code).
   */
  @Nullable()
  public Boolean getIncludeExtensionSource()
  {
    return includeExtensionSource;
  }



  /**
   * Specifies the value of a flag that indicates whether the support data
   * archive should include source code (if available) for any third-party
   * extensions installed in the server.
   *
   * @param  includeExtensionSource  The value of a flag that indicates whether
   *                                 the support data archive should include
   *                                 source code (if available) for any
   *                                 third-party extensions in the server.  It
   *                                 may be {@code null} if the property should
   *                                 not be specified when the requets is
   *                                 created (in which case the server will use
   *                                 a default behavior of excluding extension
   *                                 source code).
   */
  public void setIncludeExtensionSource(
                   @Nullable final Boolean includeExtensionSource)
  {
    this.includeExtensionSource = includeExtensionSource;
  }



  /**
   * Retrieves the value of a flag that indicates whether the server should
   * collect items for the support data archive in sequential mode rather than
   * in parallel.  Collecting data in sequential mode may reduce the amount of
   * memory consumed during the collection process, but it will take longer to
   * complete.
   *
   * @return  The value of a flag that indicates whether the server should
   *          collect items for the support data archive in sequential mode
   *          rather than in parallel, or {@code null} if the property should
   *          not be specified when the request is created (in which case the
   *          server will default to capturing data in parallel).
   */
  @Nullable()
  public Boolean getUseSequentialMode()
  {
    return useSequentialMode;
  }



  /**
   * Specifies the value of a flag that indicates whether the server should
   * collect items for the support data archive in sequential mode rather than
   * in parallel.  Collecting data in sequential mode may reduce the amount of
   * memory consumed during the collection process, but it will take longer to
   * complete.
   *
   * @param  useSequentialMode  The value of a flag that indicates whether the
   *                            server should collect items for the support data
   *                            archive in sequential mode rather than in
   *                            parallel.  It may be {@code null} if the
   *                            property should not be specified when the
   *                            request is created (in which case the server
   *                            will default to capturing data in parallel).
   */
  public void setUseSequentialMode(@Nullable final Boolean useSequentialMode)
  {
    this.useSequentialMode = useSequentialMode;
  }



  /**
   * Retrieves the security level that should be used to indicate which data
   * should be obscured, redacted, or omitted from the support data archive.
   *
   * @return  The security level that should be used when creating the support
   *          data archive, or {@code null} if the property should not be
   *          specified when the request is created (in which case the server
   *          will use a default security level).
   */
  @Nullable()
  public CollectSupportDataSecurityLevel getSecurityLevel()
  {
    return securityLevel;
  }



  /**
   * Specifies the security level that should be used to indicate which data
   * should be obscured, redacted, or omitted from the support data archive.
   *
   * @param  securityLevel  The security level that should be used when creating
   *                        the support data archive.  It may be {@code null} if
   *                        the property should not be specified when the
   *                        request is created (in which case the server will
   *                        use a default security level).
   */
  public void setSecurityLevel(
       @Nullable final CollectSupportDataSecurityLevel securityLevel)
  {
    this.securityLevel = securityLevel;
  }



  /**
   * Retrieves the number of times that the jstack utility should be invoked to
   * obtain stack traces from all threads in the server.
   *
   * @return  The number of times that the jstack utility should be invoked to
   *          obtain stack traces from all threads in the server, or
   *          {@code null} if the property should not be specified when the
   *          request is created (in which case the server will use a default
   *          count).
   */
  @Nullable()
  public Integer getJStackCount()
  {
    return jstackCount;
  }



  /**
   * Specifies the number of times that the jstack utility should be invoked to
   * obtain stack traces from all threads in the server.
   *
   * @param  jstackCount  The number of times that the jstack utility should be
   *                      invoked to obtain stack traces from all threads in the
   *                      server.  The value must not be negative, but it may be
   *                      zero to indicate that the jstack utility should not be
   *                      invoked.  It may be {@code null} if the property
   *                      should not be specified when the request is created
   *                      (in which case the server will use a default count).
   */
  public void setJStackCount(@Nullable final Integer jstackCount)
  {
    if (jstackCount != null)
    {
      Validator.ensureTrue((jstackCount >= 0),
           "If CollectSupportDataExtendedRequestProperties.jstackCount is " +
                "non-null, then the value must be greater than or equal to " +
                "zero.");
    }

    this.jstackCount = jstackCount;
  }



  /**
   * Retrieves the number of intervals that should be captured from tools that
   * use interval-based sampling (e.g., vmstat, iostat, mpstat, etc.).
   *
   * @return  The number of intervals that should be captured from tools that
   *          use interval-based sampling, or {@code null} if the property
   *          should not be specified when the request is created (in which case
   *          the server will use a default report count).
   */
  @Nullable()
  public Integer getReportCount()
  {
    return reportCount;
  }



  /**
   * Specifies the number of intervals that should be captured form tools that
   * use interval-based sampling (e.g., vmstat, iostat, mpstat, etc.).
   *
   * @param  reportCount  The number of intervals that should be captured from
   *                      tools that use interval-based sampling.  The value
   *                      must not be negative, but it may be zero to indicate
   *                      that no intervals should be captured.  It may be
   *                      {@code null} if the property should not be specified
   *                      when the request is created (in which case the server
   *                      will use a default report count).
   */
  public void setReportCount(@Nullable final Integer reportCount)
  {
    if (reportCount != null)
    {
      Validator.ensureTrue((reportCount >= 0),
           "If CollectSupportDataExtendedRequestProperties.reportCount is " +
                "non-null, then the value must be greater than or equal to " +
                "zero.");
    }

    this.reportCount = reportCount;
  }



  /**
   * Retrieves the interval duration in seconds that should be used for tools
   * that use interval-based sampling (e.g., vmstat, iostat, mpstat, etc.).
   *
   * @return  The interval duration in seconds that should be used for tools
   *          that use interval-based sampling, or {@code null} if the property
   *          should not be specified when the request is created (in which case
   *          the server will use a default report interval).
   */
  @Nullable()
  public Integer getReportIntervalSeconds()
  {
    return reportIntervalSeconds;
  }



  /**
   * Specifies the interval duration in seconds that should be used for tools
   * that use interval-based sampling (e.g., vmstat, iostat, mpstat, etc.).
   *
   * @param  reportIntervalSeconds  The interval duration in seconds that should
   *                                be used for tools that use interval-based
   *                                sampling.  The value must be greater than or
   *                                equal to one.  It may be {@code null} if the
   *                                property should not be specified when the
   *                                request is created (in which case the server
   *                                will use a default report count).
   */
  public void setReportIntervalSeconds(
                   @Nullable final Integer reportIntervalSeconds)
  {
    if (reportIntervalSeconds != null)
    {
      Validator.ensureTrue((reportIntervalSeconds > 0),
           "If CollectSupportDataExtendedRequestProperties." +
                "reportIntervalSeconds is non-null, then the value must be " +
                "greater than zero.");
    }

    this.reportIntervalSeconds = reportIntervalSeconds;
  }



  /**
   * Retrieves the log capture window object that indicates how much log content
   * should be included in the support data archive.
   *
   * @return  The log capture window object that indicates how much log content
   *          should be included in the support data archive, or {@code null}
   *          if this should not be specified in the request and the server
   *          should choose an appropriate amount of log content.
   */
  @Nullable()
  public CollectSupportDataLogCaptureWindow getLogCaptureWindow()
  {
    return logCaptureWindow;
  }



  /**
   * Specifies the log capture window object that indicates how much log content
   * should be included in the support data archive.
   *
   * @param  logCaptureWindow  The log capture window object that indicates how
   *                           much log content should be included in the
   *                           support data archive.  It may be {@code null} to
   *                           indicate that the server should choose an
   *                           appropriate amount of log content.
   */
  public void setLogCaptureWindow(
       @Nullable final CollectSupportDataLogCaptureWindow logCaptureWindow)
  {
    this.logCaptureWindow = logCaptureWindow;
  }



  /**
   * Retrieves an additional comment that should be included in the support data
   * archive.
   *
   * @return  An additional comment that should be included in the support data
   *          archive, or {@code null} if no comment should be included.
   */
  @Nullable()
  public String getComment()
  {
    return comment;
  }



  /**
   * Specifies an additional comment that should be included in the support data
   * archive.
   *
   * @param  comment  An additional comment that should be included in the
   *                  support data archive.  It may be {@code null} if no
   *                  additional comment should be included.
   */
  public void setComment(@Nullable final String comment)
  {
    this.comment = comment;
  }



  /**
   * Retrieves the address of the backend Directory Server to which the collect
   * support data extended request should be forwarded.
   *
   * @return  The address of the backend Directory Server to which the collect
   *          support data extended request should be forwarded, or {@code null}
   *          if the request should be processed directly by the server that
   *          receives it.
   */
  @Nullable()
  public String getProxyToServerAddress()
  {
    return proxyToServerAddress;
  }



  /**
   * Retrieves the port of the backend Directory Server to which the collect
   * support data extended request should be forwarded.
   *
   * @return  The port of the backend Directory Server to which the collect
   *          support data extended request should be forwarded, or {@code null}
   *          if the request should be processed directly by the server that
   *          receives it.
   */
  @Nullable()
  public Integer getProxyToServerPort()
  {
    return proxyToServerPort;
  }



  /**
   * Specifies the address and port of the backend Directory Server to which the
   * collect support data extended request should be forwarded.  Either both
   * arguments must be {@code null} or both must be non-{@code null}.
   *
   * @param  address  The address of the backend Directory Server to which the
   *                  request should be forwarded.  It may be {@code null} if
   *                  the request should be processed directly by the server
   *                  that receives it, in which case the {@code port} value
   *                  must also be {@code null}.  If it is non-{@code null},
   *                  then it must also be non-empty.
   * @param  port     The port of the backend Directory Server to which the
   *                  request should be forwarded.  It may be {@code nuoll} if
   *                  the request should be processed directly by the server
   *                  that receives it, in which case the {@code address} value
   *                  must also be non-{@code null}.  If it is non-{@code null},
   *                  then the value must be between 1 and 65535, inclusive.
   */
  public void setProxyToServer(@Nullable final String address,
                               @Nullable final Integer port)
  {
    if (address == null)
    {
      Validator.ensureTrue((port == null),
           "If CollectSupportDataExtendedRequestProperties.proxyToServer." +
                "address is null, then " +
                "CollectSupportDataExtendedRequestProperties.proxyToServer." +
                "port must also be null.");
    }
    else
    {
      Validator.ensureFalse(address.isEmpty(),
           "If CollectSupportDataExtendedRequestProperties.proxyToServer." +
                "address is non-null, then it must also be non-empty.");
      Validator.ensureNotNullWithMessage(port,
           "If CollectSupportDataExtendedRequestProperties.proxyToServer." +
                "address is non-null, then " +
                "CollectSupportDataExtendedRequestProperties.proxyToServer." +
                "port must also be non-null.");
      Validator.ensureTrue(((port >= 1) && (port <= 65535)),
           "If CollectSupportDataExtendedRequestProperties.proxyToServer." +
                "port is non-null, then its value must be between 1 and " +
                "65535, inclusive.");
    }

    proxyToServerAddress = address;
    proxyToServerPort = port;
  }



  /**
   * Retrieves the maximum size, in bytes, that may be used for a support data
   * archive fragment returned in any single
   * {@link CollectSupportDataArchiveFragmentIntermediateResponse} message.
   *
   * @return  The maximum size, in bytes, that may be used for a support data
   *          archive fragment in any single archive fragment intermediate
   *          response message, or {@code null} if the server should use a
   *          default maximum fragment size.
   */
  @Nullable()
  public Integer getMaximumFragmentSizeBytes()
  {
    return maximumFragmentSizeBytes;
  }



  /**
   * Specifies the maximum size, in bytes, that may be used for a support data
   * archive fragment returned in any single
   * {@link CollectSupportDataArchiveFragmentIntermediateResponse} message.
   *
   * @param  maximumFragmentSizeBytes  The maximum size, in bytes, that may be
   *                                   used for a support data archive fragment
   *                                   returned in any single archive fragment
   *                                   intermediate response message.  It may be
   *                                   {@code null} if the server should use a
   *                                   default maximum fragment size.  If it is
   *                                   non-{@code null}, then the value must
   *                                   also be greater than zero.
   */
  public void setMaximumFragmentSizeBytes(
                   @Nullable final Integer maximumFragmentSizeBytes)
  {
    if (maximumFragmentSizeBytes != null)
    {
      Validator.ensureTrue((maximumFragmentSizeBytes > 0),
           "If CollectSupportDataExtendedRequestProperties." +
                "maximumFragmentSizeBytes is non-null, then its value must " +
                "be greater than zero.");
    }

    this.maximumFragmentSizeBytes = maximumFragmentSizeBytes;
  }



  /**
   * Retrieves a string representation of this collect support data request
   * properties object.
   *
   * @return  A string representation of this collect support data request
   *          properties object.
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
   * Appends a string representation of this collect support data request
   * properties object to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation will be
   *                 appended.  It must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("CollectSupportDataArchiveProperties(");
    appendNameValuePair(buffer, "archiveFileName", archiveFileName);

    if (encryptionPassphrase != null)
    {
      appendNameValuePair(buffer, "encryptionPassphrase", "*****REDACTED*****");
    }

    appendNameValuePair(buffer, "includeExpensiveData", includeExpensiveData);
    appendNameValuePair(buffer, "includeReplicationStateDump",
         includeReplicationStateDump);
    appendNameValuePair(buffer, "includeBinaryFiles", includeBinaryFiles);
    appendNameValuePair(buffer, "includeExtensionSource",
         includeExtensionSource);
    appendNameValuePair(buffer, "securityLevel", securityLevel);
    appendNameValuePair(buffer, "useSequentialMode", useSequentialMode);
    appendNameValuePair(buffer, "jstackCount", jstackCount);
    appendNameValuePair(buffer, "reportCount", reportCount);
    appendNameValuePair(buffer, "reportIntervalSeconds", reportIntervalSeconds);
    appendNameValuePair(buffer, "logCaptureWindow", logCaptureWindow);
    appendNameValuePair(buffer, "comment", comment);
    appendNameValuePair(buffer, "proxyToServerAddress", proxyToServerAddress);
    appendNameValuePair(buffer, "proxyToServerPort", proxyToServerPort);
    appendNameValuePair(buffer, "maximumFragmentSizeBytes",
         maximumFragmentSizeBytes);

    buffer.append(')');
  }



  /**
   * Appends a name-value pair to the provided buffer, if the value is
   * non-{@code null}.
   *
   * @param  buffer  The buffer to which the name-value pair should be appended.
   * @param  name    The name to be used.  It must not be {@code null}.
   * @param  value   The value to be used.  It may be {@code null} if there is
   *                 no value for the property.
   */
  private static void appendNameValuePair(@NotNull final StringBuilder buffer,
               @NotNull final String name,
               @Nullable final Object value)
  {
    if (value == null)
    {
      return;
    }

    if ((buffer.length() > 0) &&
         (buffer.charAt(buffer.length() - 1) != '('))
    {
      buffer.append(", ");
    }

    buffer.append(name);
    buffer.append('=');

    if ((value instanceof Boolean) || (value instanceof Integer) ||
         (value instanceof CollectSupportDataLogCaptureWindow))
    {
      buffer.append(value);
    }
    else
    {
      buffer.append('\'');
      buffer.append(value);
      buffer.append('\'');
    }
  }
}
