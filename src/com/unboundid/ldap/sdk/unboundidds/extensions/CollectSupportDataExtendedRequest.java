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



import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.IntermediateResponseListener;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPRuntimeException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.tasks.CollectSupportDataSecurityLevel;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request that may be used
 * to invoke the collect-support data tool in a Ping Identity Directory Server
 * and stream the output (using
 * {@link CollectSupportDataOutputIntermediateResponse} messages) and the
 * resulting support data archive (using
 * {@link CollectSupportDataArchiveFragmentIntermediateResponse} messages)
 * back to the client before the final
 * {@link CollectSupportDataExtendedResult} response.
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
 * <BR>
 * The collect support data extended request has an OID of
 * 1.3.6.1.4.1.30221.2.6.64 and a value with the following encoding:
 * <BR>
 * <PRE>
 *   CollectSupportDataRequest ::= SEQUENCE {
 *      archiveFileName                 [0]  OCTET STRING OPTIONAL,
 *      encryptionPassphrase            [1]  OCTET STRING OPTIONAL,
 *      includeExpensiveData            [2]  BOOLEAN DEFAULT FALSE,
 *      includeReplicationStateDump     [3]  BOOLEAN DEFAULT FALSE,
 *      includeBinaryFiles              [4]  BOOLEAN DEFAULT FALSE,
 *      includeExtensionSource          [5]  BOOLEAN DEFAULT FALSE,
 *      useSequentialMode               [6]  BOOLEAN DEFAULT FALSE,
 *      securityLevel                   [7]  ENUMERATED {
 *           none                            (0),
 *           obscureSecrets                  (1),
 *           maximum                         (2),
 *           ... } DEFAULT obscureSecrets,
 *      jstackCount                     [8]  INTEGER (0..MAX) DEFAULT 10,
 *      reportCount                     [9]  INTEGER (0..MAX) DEFAULT 10,
 *      reportIntervalSeconds           [10] INTEGER (1..MAX) DEFAULT 1,
 *      logCaptureWindow                [11] CHOICE {
 *           toolDefault                     [0] NULL,
 *           durationMillis                  [1] INTEGER (0..MAX),
 *           timeWindow                      [2] SEQUENCE {
 *                startTime                       OCTET STRING,
 *                endTime                         OCTET STRING OPTIONAL },
 *           headAndTailSize                 [3] SEQUENCE {
 *                headSizeKB                      [0] INTEGER OPTIONAL,
 *                tailSizeKB                      [1] INTEGER OPTIONAL },
 *           ... } DEFAULT default,
 *      comment                         [12] OCTET STRING OPTIONAL,
 *      proxyToServer                   [13] SEQUENCE OF {
 *           address                         OCTET STRING,
 *           port                            INTEGER (1..65535),
 *           ... } OPTIONAL,
 *      maximumFragmentSizeBytes        [1] INTEGER DEFAULT 1048576,
 *      ... }
 * </PRE>
 * <BR><BR>
 * Because the tool output and the support data archive will be streamed back to
 * the client using intermediate response messages, the request must be
 * configured with an intermediate response listener to gain access to that
 * information.
 *
 * @see  CollectSupportDataExtendedResult
 * @see  CollectSupportDataOutputIntermediateResponse
 * @see  CollectSupportDataArchiveFragmentIntermediateResponse
 * @see  CollectSupportDataSecurityLevel
 * @see  CollectSupportDataLogCaptureWindow
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CollectSupportDataExtendedRequest
       extends ExtendedRequest
       implements IntermediateResponseListener
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.64) for the collect support data extended
   * request.
   */
  @NotNull public static final String COLLECT_SUPPORT_DATA_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.64";



  /**
   * The BER type for the request element that specifies the name to use for the
   * archive file.
   */
  private static final byte TYPE_ARCHIVE_FILE_NAME = (byte) 0x80;



  /**
   * The BER type for the request element that specifies the passphrase to use
   * to encrypt the contents of the support data archive.
   */
  static final byte TYPE_ENCRYPTION_PASSPHRASE = (byte) 0x81;



  /**
   * The BER type for the request element that indicates whether to include
   * data that may be expensive to collect.
   */
  private static final byte TYPE_INCLUDE_EXPENSIVE_DATA = (byte) 0x82;



  /**
   * The BER type for the request element that indicates whether to include a
   * replication state dump.
   */
  private static final byte TYPE_INCLUDE_REPLICATION_STATE_DUMP = (byte) 0x83;



  /**
   * The BER type for the request element that indicates whether to include
   * binary files.
   */
  private static final byte TYPE_INCLUDE_BINARY_FILES = (byte) 0x84;



  /**
   * The BER type for the request element that indicates whether to include
   * extension source code.
   */
  private static final byte TYPE_INCLUDE_EXTENSION_SOURCE = (byte) 0x85;



  /**
   * The BER type for the request element that indicates whether to collect
   * information in sequential mode.
   */
  private static final byte TYPE_USE_SEQUENTIAL_MODE = (byte) 0x86;



  /**
   * The BER type for the request element that specifies the security level.
   */
  private static final byte TYPE_SECURITY_LEVEL = (byte) 0x87;



  /**
   * The BER type for the request element that specifies the number of jstack
   * stack traces to include.
   */
  private static final byte TYPE_JSTACK_COUNT = (byte) 0x88;



  /**
   * The BER type for the request element that specifies the number intervals
   * to collect from interval-based sampling tools.
   */
  private static final byte TYPE_REPORT_COUNT = (byte) 0x89;



  /**
   * The BER type for the request element that specifies the interval duration
   * to use for interval-based sampling tools.
   */
  private static final byte TYPE_REPORT_INTERVAL_SECONDS = (byte) 0x8A;



  /**
   * The BER type for the request element that specifies the log capture window
   * for the request.
   */
  private static final byte TYPE_LOG_CAPTURE_WINDOW = (byte) 0xAB;



  /**
   * The BER type for the request element that specifies a comment to include in
   * the archive.
   */
  private static final byte TYPE_COMMENT = (byte) 0x8C;



  /**
   * The BER type for the request element that specifies the address and port
   * to which the request should be forwarded.
   */
  private static final byte TYPE_PROXY_TO_SERVER = (byte) 0xAD;



  /**
   * The BER type for the request element that specifies the maximum archive
   * fragment size.
   */
  private static final byte TYPE_MAXIMUM_FRAGMENT_SIZE_BYTES = (byte) 0x8E;



  /**
   * The integer value for the {@link CollectSupportDataSecurityLevel#NONE}
   * security level.
   */
  private static final int SECURITY_LEVEL_VALUE_NONE = 0;



  /**
   * The integer value for the
   * {@link CollectSupportDataSecurityLevel#OBSCURE_SECRETS} security level.
   */
  private static final int SECURITY_LEVEL_VALUE_OBSCURE_SECRETS = 1;



  /**
   * The integer value for the {@link CollectSupportDataSecurityLevel#MAXIMUM}
   * security level.
   */
  private static final int SECURITY_LEVEL_VALUE_MAXIMUM = 2;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8884596371195896085L;



  // The passphrase to use to encrypt the contents of the support data archive.
  @Nullable private final ASN1OctetString encryptionPassphrase;

  // Indicates whether to include binary files in the support data archive.
  @Nullable private final Boolean includeBinaryFiles;

  // Indicates whether to include expensive data in the support data archive.
  @Nullable private final Boolean includeExpensiveData;

  // Indicates whether to include third-party extension source code in the
  // support data archive.
  @Nullable private final Boolean includeExtensionSource;

  // Indicates whether to include a replication state dump in the support data
  // archive.
  @Nullable private final Boolean includeReplicationStateDump;

  // Indicates whether to capture information sequentially rather than in
  // parallel.
  @Nullable private final Boolean useSequentialMode;

  // The intermediate response listener that will be used for this operation.
  @NotNull private final CollectSupportDataIntermediateResponseListener
       intermediateResponseListener;

  // The log capture window that indicates how much log content to include in
  // the support data archive.
  @Nullable private final CollectSupportDataLogCaptureWindow logCaptureWindow;

  // The security level to use for data included in the support data archive.
  @Nullable private final CollectSupportDataSecurityLevel securityLevel;

  // The number of jstacks to include in the support data archive.
  @Nullable private final Integer jstackCount;

  // The maximum size, in bytes, of any support data archive fragment to include
  // in a collect support data archive fragment intermediate response.
  @Nullable private final Integer maximumFragmentSizeBytes;

  // The port of a backend Directory Server instance to which the collect
  // support data extended request should be forwarded.
  @Nullable private final Integer proxyToServerPort;

  // The report count to use for sampled metrics.
  @Nullable private final Integer reportCount;

  // The report interval in seconds to use for sampled metrics.
  @Nullable private final Integer reportIntervalSeconds;

  // The name (without any path information) the client intends to use for the
  // support data archive file.
  @Nullable private final String archiveFileName;

  // A comment to include in the support data archive.
  @Nullable private final String comment;

  // The address of a backend Directory Server to which the collect support data
  // extended request should be forwarded.
  @Nullable private final String proxyToServerAddress;



  /**
   * Creates a new instance of this extended request with the provided
   * information.
   *
   * @param  properties                    The properties that should be used
   *                                       for the collect support data extended
   *                                       request.  It must not be
   *                                       {@code null}.
   * @param  intermediateResponseListener  The listener that will be used to
   *                                       handle any intermediate response
   *                                       messages that are received in the
   *                                       course of processing the collect
   *                                       support data extended request.  It
   *                                       must not be {@code null}.
   * @param  controls                      The controls to include in the
   *                                       collect support data extended
   *                                       request.  It may be {@code null} or
   *                                       empty if no controls are needed.
   */
  public CollectSupportDataExtendedRequest(
       @NotNull final CollectSupportDataExtendedRequestProperties properties,
       @NotNull final CollectSupportDataIntermediateResponseListener
            intermediateResponseListener,
       @Nullable final Control... controls)
  {
    super(COLLECT_SUPPORT_DATA_REQUEST_OID, encodeValue(properties), controls);

    Validator.ensureNotNullWithMessage(intermediateResponseListener,
         "CollectSupportDataExtendedRequest.intermediateResponseListener " +
              "must not be null.");
    this.intermediateResponseListener = intermediateResponseListener;

    archiveFileName = properties.getArchiveFileName();
    encryptionPassphrase = properties.getEncryptionPassphrase();
    includeBinaryFiles = properties.getIncludeBinaryFiles();
    includeExpensiveData = properties.getIncludeExpensiveData();
    includeExtensionSource = properties.getIncludeExtensionSource();
    includeReplicationStateDump = properties.getIncludeReplicationStateDump();
    useSequentialMode = properties.getUseSequentialMode();
    logCaptureWindow = properties.getLogCaptureWindow();
    securityLevel = properties.getSecurityLevel();
    jstackCount = properties.getJStackCount();
    reportCount = properties.getReportCount();
    reportIntervalSeconds = properties.getReportIntervalSeconds();
    maximumFragmentSizeBytes = properties.getMaximumFragmentSizeBytes();
    proxyToServerPort = properties.getProxyToServerPort();
    comment = properties.getComment();
    proxyToServerAddress = properties.getProxyToServerAddress();

    setIntermediateResponseListener(this);
  }



  /**
   * Constructs an ASN.1 octet string suitable for use as the value of this
   * collect support data extended request from the given set of properties.
   *
   * @param  properties  The properties that should be used to construct the
   *                     extended request value.  It must not be {@code null}.
   *
   * @return  the ASN.1 octet string that was created.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
       @NotNull final CollectSupportDataExtendedRequestProperties properties)
  {
    final List<ASN1Element> elements = new ArrayList<>(20);

    final String archiveFileName = properties.getArchiveFileName();
    if (archiveFileName != null)
    {
      elements.add(new ASN1OctetString(TYPE_ARCHIVE_FILE_NAME,
           archiveFileName));
    }

    final ASN1OctetString encryptionPassphrase =
         properties.getEncryptionPassphrase();
    if (encryptionPassphrase != null)
    {
      elements.add(encryptionPassphrase);
    }

    final Boolean includeExpensiveData = properties.getIncludeExpensiveData();
    if (includeExpensiveData != null)
    {
      elements.add(new ASN1Boolean(TYPE_INCLUDE_EXPENSIVE_DATA,
           includeExpensiveData));
    }

    final Boolean includeReplicationStateDump =
         properties.getIncludeReplicationStateDump();
    if (includeReplicationStateDump != null)
    {
      elements.add(new ASN1Boolean(TYPE_INCLUDE_REPLICATION_STATE_DUMP,
           includeReplicationStateDump));
    }

    final Boolean includeBinaryFiles = properties.getIncludeBinaryFiles();
    if (includeBinaryFiles != null)
    {
      elements.add(new ASN1Boolean(TYPE_INCLUDE_BINARY_FILES,
           includeBinaryFiles));
    }

    final Boolean includeExtensionSource =
         properties.getIncludeExtensionSource();
    if (includeExtensionSource != null)
    {
      elements.add(new ASN1Boolean(TYPE_INCLUDE_EXTENSION_SOURCE,
           includeExtensionSource));
    }

    final Boolean useSequentialMode = properties.getUseSequentialMode();
    if (useSequentialMode != null)
    {
      elements.add(new ASN1Boolean(TYPE_USE_SEQUENTIAL_MODE,
           useSequentialMode));
    }

    final CollectSupportDataSecurityLevel securityLevel =
         properties.getSecurityLevel();
    if (securityLevel != null)
    {
      final int securityLevelIntValue;
      switch (securityLevel)
      {
        case NONE:
          securityLevelIntValue = SECURITY_LEVEL_VALUE_NONE;
          break;
        case OBSCURE_SECRETS:
          securityLevelIntValue = SECURITY_LEVEL_VALUE_OBSCURE_SECRETS;
          break;
        case MAXIMUM:
          securityLevelIntValue = SECURITY_LEVEL_VALUE_MAXIMUM;
          break;
        default:
          throw new LDAPRuntimeException(new LDAPException(
               ResultCode.LOCAL_ERROR,
               ERR_CSD_REQUEST_UNSUPPORTED_SECURITY_LEVEL.get(
                    securityLevel.getName())));
      }

      elements.add(new ASN1Enumerated(TYPE_SECURITY_LEVEL,
           securityLevelIntValue));
    }

    final Integer jstackCount = properties.getJStackCount();
    if (jstackCount != null)
    {
      elements.add(new ASN1Integer(TYPE_JSTACK_COUNT, jstackCount));
    }

    final Integer reportCount = properties.getReportCount();
    if (reportCount != null)
    {
      elements.add(new ASN1Integer(TYPE_REPORT_COUNT, reportCount));
    }

    final Integer reportIntervalSeconds =
         properties.getReportIntervalSeconds();
    if (reportIntervalSeconds != null)
    {
      elements.add(new ASN1Integer(TYPE_REPORT_INTERVAL_SECONDS,
           reportIntervalSeconds));
    }

    final CollectSupportDataLogCaptureWindow logCaptureWindow =
         properties.getLogCaptureWindow();
    if (logCaptureWindow != null)
    {
      elements.add(new ASN1Element(TYPE_LOG_CAPTURE_WINDOW,
           logCaptureWindow.encode().encode()));
    }

    final String comment = properties.getComment();
    if (comment != null)
    {
      elements.add(new ASN1OctetString(TYPE_COMMENT, comment));
    }

    final String proxyToServerAddress = properties.getProxyToServerAddress();
    if (proxyToServerAddress != null)
    {
      elements.add(new ASN1Sequence(TYPE_PROXY_TO_SERVER,
           new ASN1OctetString(proxyToServerAddress),
           new ASN1Integer(properties.getProxyToServerPort())));
    }

    final Integer maximumFragmentSizeBytes =
         properties.getMaximumFragmentSizeBytes();
    if (maximumFragmentSizeBytes != null)
    {
      elements.add(new ASN1Integer(TYPE_MAXIMUM_FRAGMENT_SIZE_BYTES,
           maximumFragmentSizeBytes));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Creates a new collect support data extended request that is decoded from
   * the provided generic extended request.
   *
   * @param  request                       The generic extended request to be
   *                                       decoded as a collect support data
   *                                       extended request.  It must not be
   *                                       {@code null}.
   * @param  intermediateResponseListener  The listener that will be used to
   *                                       handle any intermediate response
   *                                       messages that are received in the
   *                                       course of processing the collect
   *                                       support data extended request.  It
   *                                       must not be {@code null}.
   *
   * @throws  LDAPException  If the provided extended request cannot be decoded
   *                         as a valid collect support data extended request.
   */
  public CollectSupportDataExtendedRequest(
              @NotNull final ExtendedRequest request,
              @NotNull final CollectSupportDataIntermediateResponseListener
                   intermediateResponseListener)
         throws LDAPException
  {
    super(request);

    Validator.ensureNotNullWithMessage(intermediateResponseListener,
         "CollectSupportDataExtendedRequest.intermediateResponseListener " +
              "must not be null.");
    this.intermediateResponseListener = intermediateResponseListener;

    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CSD_REQUEST_DECODE_NO_VALUE.get());
    }

    try
    {
      ASN1OctetString encPassphrase = null;
      Boolean includeExpensive = null;
      Boolean includeReplication = null;
      Boolean includeBinary = null;
      Boolean includeSource = null;
      Boolean sequentialMode = null;
      CollectSupportDataSecurityLevel secLevel = null;
      Integer jCount = null;
      Integer rCount = null;
      Integer rInterval = null;
      CollectSupportDataLogCaptureWindow lcw = null;
      String archiveName = null;
      String commentStr = null;
      String proxyToAddress = null;
      Integer proxyToPort = null;
      Integer maxFragmentSize = null;

      final ASN1Sequence valueSequence =
           ASN1Sequence.decodeAsSequence(value.getValue());
      final ASN1Element[] elements = valueSequence.elements();
      for (final ASN1Element e : elements)
      {
        switch (e.getType())
        {
          case TYPE_ARCHIVE_FILE_NAME:
            archiveName = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_ENCRYPTION_PASSPHRASE:
            encPassphrase = ASN1OctetString.decodeAsOctetString(e);
            break;
          case TYPE_INCLUDE_EXPENSIVE_DATA:
            includeExpensive = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_INCLUDE_REPLICATION_STATE_DUMP:
            includeReplication = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_INCLUDE_BINARY_FILES:
            includeBinary = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_INCLUDE_EXTENSION_SOURCE:
            includeSource  = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_USE_SEQUENTIAL_MODE:
            sequentialMode  = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_SECURITY_LEVEL:
            final int secLevelIntValue =
                 ASN1Enumerated.decodeAsEnumerated(e).intValue();
            switch (secLevelIntValue)
            {
              case SECURITY_LEVEL_VALUE_NONE:
                secLevel = CollectSupportDataSecurityLevel.NONE;
                break;
              case SECURITY_LEVEL_VALUE_OBSCURE_SECRETS:
                secLevel = CollectSupportDataSecurityLevel.OBSCURE_SECRETS;
                break;
              case SECURITY_LEVEL_VALUE_MAXIMUM:
                secLevel = CollectSupportDataSecurityLevel.MAXIMUM;
                break;
              default:
                throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_CSD_REQUEST_DECODE_UNSUPPORTED_SECURITY_LEVEL.get(
                          secLevelIntValue));
            }
            break;
          case TYPE_JSTACK_COUNT:
            jCount = ASN1Integer.decodeAsInteger(e).intValue();
            break;
          case TYPE_REPORT_COUNT:
            rCount = ASN1Integer.decodeAsInteger(e).intValue();
            break;
          case TYPE_REPORT_INTERVAL_SECONDS:
            rInterval = ASN1Integer.decodeAsInteger(e).intValue();
            break;
          case TYPE_LOG_CAPTURE_WINDOW:
            final ASN1Element lcwElement = ASN1Element.decode(e.getValue());
            try
            {
              lcw = CollectSupportDataLogCaptureWindow.decode(lcwElement);
            }
            catch (final Exception ex)
            {
              Debug.debugException(ex);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_CSD_REQUEST_DECODE_LCW_FAILED.get(
                        StaticUtils.getExceptionMessage(ex)),
                   ex);
            }
            break;
          case TYPE_COMMENT:
            commentStr = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_PROXY_TO_SERVER:
            final ASN1Element[] proxyToElements =
                 ASN1Sequence.decodeAsSequence(e).elements();
            proxyToAddress = ASN1OctetString.decodeAsOctetString(
                 proxyToElements[0]).stringValue();
            proxyToPort = ASN1Integer.decodeAsInteger(
                 proxyToElements[1]).intValue();
            break;
          case TYPE_MAXIMUM_FRAGMENT_SIZE_BYTES:
            maxFragmentSize = ASN1Integer.decodeAsInteger(e).intValue();
            break;
        }
      }

      archiveFileName = archiveName;
      encryptionPassphrase = encPassphrase;
      includeExpensiveData = includeExpensive;
      includeReplicationStateDump = includeReplication;
      includeBinaryFiles = includeBinary;
      includeExtensionSource = includeSource;
      useSequentialMode = sequentialMode;
      securityLevel = secLevel;
      jstackCount = jCount;
      reportCount = rCount;
      reportIntervalSeconds = rInterval;
      logCaptureWindow = lcw;
      comment = commentStr;
      proxyToServerAddress = proxyToAddress;
      proxyToServerPort = proxyToPort;
      maximumFragmentSizeBytes = maxFragmentSize;
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CSD_REQUEST_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the listener that will be notified when any output, archive
   * fragment, or other types of intermediate response messages are received
   * in response to this extended request.
   *
   * @return  The listener that will be notified when any output, archive
   *          fragment, or other types of intermediate response messages are
   *          in response to this extended request.
   */
  @NotNull()
  public CollectSupportDataIntermediateResponseListener
              getCollectSupportDataIntermediateResponseListener()
  {
    return intermediateResponseListener;
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
   * Retrieves the value of a flag that indicates whether the support data
   * archive may include data that is potentially expensive to collect and
   * could affect the performance or responsiveness of the server.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive may include data that is potentially expensive to collect,
   *          or {@code null} if the property should not be specified when the
   *          task is created (in which case the server will use a default
   *          behavior of excluding expensive data).
   */
  @Nullable()
  public Boolean getIncludeExpensiveData()
  {
    return includeExpensiveData;
  }



  /**
   * Retrieves the value of a flag that indicates whether the support data
   * archive may include a replication state dump, which may be several
   * megabytes in size.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive may include a replication state dump, or {@code null} if
   *          the property should not be specified when the task is created (in
   *          which case the server will use a default behavior of excluding the
   *          state dump).
   */
  @Nullable()
  public Boolean getIncludeReplicationStateDump()
  {
    return includeReplicationStateDump;
  }



  /**
   * Retrieves the value of a flag that indicates whether the support data
   * archive may include binary files.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive may include binary files, or {@code null} if the property
   *          should not be specified when the task is created (in which case
   *          the server will use a default behavior of excluding binary files).
   */
  @Nullable()
  public Boolean getIncludeBinaryFiles()
  {
    return includeBinaryFiles;
  }



  /**
   * Retrieves the value of a flag that indicates whether the support data
   * archive should include source code (if available) for any third-party
   * extensions installed in the server.
   *
   * @return  The value of a flag that indicates whether the support data
   *          archive should include source code (if available) for any
   *          third-party extensions installed in the server, or {@code null} if
   *          the property should not be specified when the task is created (in
   *          which case the server will use a default behavior of excluding
   *          extension source code).
   */
  @Nullable()
  public Boolean getIncludeExtensionSource()
  {
    return includeExtensionSource;
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
   *          not be specified when the task is created (in which case the
   *          server will default to capturing data in parallel).
   */
  @Nullable()
  public Boolean getUseSequentialMode()
  {
    return useSequentialMode;
  }



  /**
   * Retrieves the security level that should be used to indicate which data
   * should be obscured, redacted, or omitted from the support data archive.
   *
   * @return  The security level that should be used when creating the support
   *          data archive, or {@code null} if the property should not be
   *          specified when the task is created (in which case the server will
   *          use a default security level).
   */
  @Nullable()
  public CollectSupportDataSecurityLevel getSecurityLevel()
  {
    return securityLevel;
  }



  /**
   * Retrieves the number of times that the jstack utility should be invoked to
   * obtain stack traces from all threads in the server.
   *
   * @return  The number of times that the jstack utility should be invoked to
   *          obtain stack traces from all threads in the server, or
   *          {@code null} if the property should not be specified when the task
   *          is created (in which case the server will use a default count).
   */
  @Nullable()
  public Integer getJStackCount()
  {
    return jstackCount;
  }



  /**
   * Retrieves the number of intervals that should be captured from tools that
   * use interval-based sampling (e.g., vmstat, iostat, mpstat, etc.).
   *
   * @return  The number of intervals that should be captured from tools that
   *          use interval-based sampling, or {@code null} if the property
   *          should not be specified when the task is created (in which case
   *          the server will use a default report count).
   */
  @Nullable()
  public Integer getReportCount()
  {
    return reportCount;
  }



  /**
   * Retrieves the interval duration in seconds that should be used for tools
   * that use interval-based sampling (e.g., vmstat, iostat, mpstat, etc.).
   *
   * @return  The interval duration in seconds that should be used for tools
   *          that use interval-based sampling, or {@code null} if the property
   *          should not be specified when the task is created (in which case
   *          the server will use a default report interval).
   */
  @Nullable()
  public Integer getReportIntervalSeconds()
  {
    return reportIntervalSeconds;
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
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public CollectSupportDataExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new CollectSupportDataExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  @NotNull()
  public CollectSupportDataExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  @NotNull()
  public CollectSupportDataExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    return new CollectSupportDataExtendedRequest(
         new CollectSupportDataExtendedRequestProperties(this),
         intermediateResponseListener, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_COLLECT_SUPPORT_DATA_REQUEST_NAME.get();
  }




  /**
   * {@inheritDoc}
   */
  @Override()
  public void intermediateResponseReturned(
                   @NotNull final IntermediateResponse intermediateResponse)
  {
    final String oid = intermediateResponse.getOID();
    if (oid == null)
    {
      intermediateResponseListener.handleOtherIntermediateResponse(
           intermediateResponse);
      return;
    }

    switch (oid)
    {
      case CollectSupportDataOutputIntermediateResponse.
           COLLECT_SUPPORT_DATA_OUTPUT_INTERMEDIATE_RESPONSE_OID:
        final CollectSupportDataOutputIntermediateResponse
             outputIntermediateResponse;
        try
        {
          outputIntermediateResponse =
               new CollectSupportDataOutputIntermediateResponse(
                    intermediateResponse);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          intermediateResponseListener.handleOtherIntermediateResponse(
               intermediateResponse);
          return;
        }

        intermediateResponseListener.handleOutputIntermediateResponse(
             outputIntermediateResponse);
        break;

      case CollectSupportDataArchiveFragmentIntermediateResponse.
           COLLECT_SUPPORT_DATA_ARCHIVE_FRAGMENT_INTERMEDIATE_RESPONSE_OID:
        final CollectSupportDataArchiveFragmentIntermediateResponse
             fragmentIntermediateResponse;
        try
        {
          fragmentIntermediateResponse =
               new CollectSupportDataArchiveFragmentIntermediateResponse(
                    intermediateResponse);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          intermediateResponseListener.handleOtherIntermediateResponse(
               intermediateResponse);
          return;
        }

        intermediateResponseListener.handleArchiveFragmentIntermediateResponse(
             fragmentIntermediateResponse);
        break;

      default:
        intermediateResponseListener.handleOtherIntermediateResponse(
             intermediateResponse);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("CollectSupportDataExtendedRequest(oid='");
    buffer.append(getOID());
    buffer.append('\'');

    if (archiveFileName != null)
    {
      buffer.append(", archiveFileName='");
      buffer.append(archiveFileName);
      buffer.append('\'');
    }

    if (encryptionPassphrase != null)
    {
      buffer.append(", encryptionPassphrase='*****REDACTED*****'");
    }

    if (includeExpensiveData != null)
    {
      buffer.append(", includeExpensiveData=");
      buffer.append(includeExpensiveData);
    }

    if (includeReplicationStateDump != null)
    {
      buffer.append(", includeReplicationStateDump=");
      buffer.append(includeReplicationStateDump);
    }

    if (includeBinaryFiles != null)
    {
      buffer.append(", includeBinaryFiles=");
      buffer.append(includeBinaryFiles);
    }

    if (includeExtensionSource != null)
    {
      buffer.append(", includeExtensionSource=");
      buffer.append(includeExtensionSource);
    }

    if (useSequentialMode != null)
    {
      buffer.append(", useSequentialMode=");
      buffer.append(useSequentialMode);
    }

    if (securityLevel != null)
    {
      buffer.append(", securityLevel='");
      buffer.append(securityLevel.getName());
      buffer.append('\'');
    }

    if (jstackCount != null)
    {
      buffer.append(", jstackCount=");
      buffer.append(jstackCount);
    }

    if (reportCount != null)
    {
      buffer.append(", reportCount=");
      buffer.append(reportCount);
    }

    if (reportIntervalSeconds != null)
    {
      buffer.append(", reportIntervalSeconds=");
      buffer.append(reportIntervalSeconds);
    }

    if (logCaptureWindow != null)
    {
      buffer.append(", logCaptureWindow=");
      logCaptureWindow.toString(buffer);
    }

    if (comment != null)
    {
      buffer.append(", comment='");
      buffer.append(comment);
      buffer.append('\'');
    }

    if (proxyToServerAddress != null)
    {
      buffer.append(", proxyToServerAddress='");
      buffer.append(proxyToServerAddress);
      buffer.append('\'');
    }

    if (proxyToServerPort != null)
    {
      buffer.append(", proxyToServerPort=");
      buffer.append(proxyToServerPort);
    }

    if (maximumFragmentSizeBytes != null)
    {
      buffer.append(", maximumFragmentSizeBytes=");
      buffer.append(maximumFragmentSizeBytes);
    }

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
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
