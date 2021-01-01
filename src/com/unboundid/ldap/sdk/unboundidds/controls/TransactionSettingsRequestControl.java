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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.ArrayList;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Long;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control that can be used to specify a number of
 * settings used for any database transaction that may be associated with the
 * associated request.  It may be included in an end transaction extended
 * request or an atomic multi-update extended request (it is not supported for
 * use in non-atomic multi-update requests).
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
 * This control has an OID of 1.3.6.1.4.1.30221.2.5.38.  It may have a
 * criticality of either {@code true} (in which case the server will reject the
 * associated operation if this control is not recognized) or {@code false} (in
 * which case the server will ignore this control if it is not recognized).  It
 * must have a value with the following encoding:
 * <PRE>
 *   TransactionSettingsRequestValue ::= SEQUENCE {
 *        transactionName              [0] OCTET STRING OPTIONAL,
 *        commitDurability             [1] ENUMERATED {
 *             nonSynchronous           (0),
 *             partiallySynchronous     (1),
 *             fullySynchronous         (2),
 *             ... } OPTIONAL,
 *        backendLockBehavior          [2] ENUMERATED {
 *             doNotAcquire                    (0),
 *             acquireAfterRetries             (1),
 *             acquireBeforeRetries            (2),
 *             acquireBeforeInitialAttempt     (3),
 *             ... } OPTIONAL,
 *        backendLockTimeoutMillis     [3] INTEGER OPTIONAL,
 *        retryAttempts                [4] INTEGER OPTIONAL,
 *        txnLockTimeout               [5] SEQUENCE {
 *             minTimeoutMillis     INTEGER,
 *             maxTimeoutMillis     INTEGER,
 *             ... } OPTIONAL,
 *        returnResponseControl        [6] BOOLEAN DEFAULT FALSE,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TransactionSettingsRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.38) for the undelete request control.
   */
  @NotNull public static final String TRANSACTION_SETTINGS_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.38";



  /**
   * The BER type for the value sequence element that specifies the name to use
   * for the transaction.
   */
  private static final byte TYPE_TXN_NAME = (byte) 0x80;



  /**
   * The BER type for the value sequence element that specifies the commit
   * durability to use.
   */
  private static final byte TYPE_COMMIT_DURABILITY = (byte) 0x81;



  /**
   * The BER type for the value sequence element that specifies the behavior
   * to use with regard to acquiring the exclusive backend lock.
   */
  private static final byte TYPE_BACKEND_LOCK_BEHAVIOR = (byte) 0x82;



  /**
   * The BER type for the value sequence element that specifies the exclusive
   * backend lock timeout.
   */
  private static final byte TYPE_BACKEND_LOCK_TIMEOUT = (byte) 0x83;



  /**
   * The BER type for the value sequence element that specifies the number of
   * retry attempts.
   */
  private static final byte TYPE_RETRY_ATTEMPTS = (byte) 0x84;



  /**
   * The BER type for the value sequence element that specifies the minimum and
   * maximum database lock timeout values.
   */
  private static final byte TYPE_TXN_LOCK_TIMEOUT = (byte) 0xA5;



  /**
   * The BER type for the value sequence element that indicates whether to
   * return a response control with transaction-related information about the
   * processing of the associated operation.
   */
  private static final byte TYPE_RETURN_RESPONSE_CONTROL = (byte) 0x86;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4749344077745581287L;



  // Indicates whether to return a response control.
  private final boolean returnResponseControl;

  // The number of times to retry if a lock conflict exception is encountered.
  @Nullable private final Integer retryAttempts;

  // The backend lock timeout, in milliseconds.
  @Nullable private final Long backendLockTimeoutMillis;

  // The maximum transaction lock timeout, in milliseconds.
  @Nullable private final Long maxTxnLockTimeoutMillis;

  // The minimum transaction lock timeout, in milliseconds.
  @Nullable private final Long minTxnLockTimeoutMillis;

  // The requested transaction name.
  @Nullable private final String transactionName;

  // The requested commit durability setting.
  @Nullable private final TransactionSettingsBackendLockBehavior
       backendLockBehavior;

  // The requested commit durability setting.
  @Nullable private final TransactionSettingsCommitDurability commitDurability;



  /**
   * Creates a new transaction settings request control with the provided
   * information.
   *
   * @param  isCritical                Indicates whether the control should be
   *                                   considered critical.
   * @param  transactionName           The name to use for the transaction.  It
   *                                   may be {@code null} if no
   *                                   client-specified transaction name is
   *                                   needed.  If a transaction name is
   *                                   provided, it will be used purely for
   *                                   informational and/or troubleshooting
   *                                   purposes.
   * @param  commitDurability          The durability level that should be used
   *                                   when committing the associated
   *                                   transaction.  It may be {@code null} if
   *                                   the server-default durability level
   *                                   should be used.
   * @param  backendLockBehavior       The behavior that should be used with
   *                                   regard to acquiring an exclusive lock for
   *                                   processing in the target backend.  It may
   *                                   be {@code null} if the server-default
   *                                   backend lock behavior should be used.
   * @param  backendLockTimeoutMillis  The maximum length of time in
   *                                   milliseconds to spend attempting to
   *                                   acquire an exclusive backend lock if it
   *                                   is needed during any part of the
   *                                   processing.  A value that of zero
   *                                   indicates that no timeout should be
   *                                   enforced.  It may be {@code null} if the
   *                                   server will determine the backend lock
   *                                   timeout that should be used.
   * @param  retryAttempts             The number of times to retry the
   *                                   associated operations in a new
   *                                   transaction if the initial attempt fails.
   *                                   If this is {@code null}, then the server
   *                                   will determine the number of retry
   *                                   attempts to make.  Note that depending on
   *                                   the backend lock behavior, the server may
   *                                   make one additional retry attempt if
   *                                   necessary after acquiring an exclusive
   *                                   backend lock.
   * @param  minTxnLockTimeoutMillis   The minimum database lock timeout that
   *                                   should be used for the associated
   *                                   transaction.  If this is specified, then
   *                                   the first attempt will use this lock
   *                                   timeout, and subsequent attempts will use
   *                                   a timeout value between this and the
   *                                   maximum database lock timeout (which must
   *                                   also be specified).  If this is
   *                                   {@code null}, then the server will
   *                                   determine the database lock timeout
   *                                   settings to use.
   * @param  maxTxnLockTimeoutMillis   The maximum database lock timeout that
   *                                   should be used for the associated
   *                                   transaction.  If this is specified, then
   *                                   the minimum database lock timeout must
   *                                   also be specified, and this value must be
   *                                   greater than or equal to the minimum lock
   *                                   timeout.  If this is {@code null}, then
   *                                   the server will determine the database
   *                                   lock timeout settings to use.
   */
  public TransactionSettingsRequestControl(final boolean isCritical,
       @Nullable final String transactionName,
       @Nullable final TransactionSettingsCommitDurability commitDurability,
       @Nullable final TransactionSettingsBackendLockBehavior
                                                backendLockBehavior,
       @Nullable final Long backendLockTimeoutMillis,
       @Nullable final Integer retryAttempts,
       @Nullable final Long minTxnLockTimeoutMillis,
       @Nullable final Long maxTxnLockTimeoutMillis)
  {
    this(isCritical, transactionName, commitDurability, backendLockBehavior,
         backendLockTimeoutMillis, retryAttempts, minTxnLockTimeoutMillis,
         maxTxnLockTimeoutMillis, false);
  }



  /**
   * Creates a new transaction settings request control with the provided
   * information.
   *
   * @param  isCritical                Indicates whether the control should be
   *                                   considered critical.
   * @param  transactionName           The name to use for the transaction.  It
   *                                   may be {@code null} if no
   *                                   client-specified transaction name is
   *                                   needed.  If a transaction name is
   *                                   provided, it will be used purely for
   *                                   informational and/or troubleshooting
   *                                   purposes.
   * @param  commitDurability          The durability level that should be used
   *                                   when committing the associated
   *                                   transaction.  It may be {@code null} if
   *                                   the server-default durability level
   *                                   should be used.
   * @param  backendLockBehavior       The behavior that should be used with
   *                                   regard to acquiring an exclusive lock for
   *                                   processing in the target backend.  It may
   *                                   be {@code null} if the server-default
   *                                   backend lock behavior should be used.
   * @param  backendLockTimeoutMillis  The maximum length of time in
   *                                   milliseconds to spend attempting to
   *                                   acquire an exclusive backend lock if it
   *                                   is needed during any part of the
   *                                   processing.  A value that of zero
   *                                   indicates that no timeout should be
   *                                   enforced.  It may be {@code null} if the
   *                                   server will determine the backend lock
   *                                   timeout that should be used.
   * @param  retryAttempts             The number of times to retry the
   *                                   associated operations in a new
   *                                   transaction if the initial attempt fails.
   *                                   If this is {@code null}, then the server
   *                                   will determine the number of retry
   *                                   attempts to make.  Note that depending on
   *                                   the backend lock behavior, the server may
   *                                   make one additional retry attempt if
   *                                   necessary after acquiring an exclusive
   *                                   backend lock.
   * @param  minTxnLockTimeoutMillis   The minimum database lock timeout that
   *                                   should be used for the associated
   *                                   transaction.  If this is specified, then
   *                                   the first attempt will use this lock
   *                                   timeout, and subsequent attempts will use
   *                                   a timeout value between this and the
   *                                   maximum database lock timeout (which must
   *                                   also be specified).  If this is
   *                                   {@code null}, then the server will
   *                                   determine the database lock timeout
   *                                   settings to use.
   * @param  maxTxnLockTimeoutMillis   The maximum database lock timeout that
   *                                   should be used for the associated
   *                                   transaction.  If this is specified, then
   *                                   the minimum database lock timeout must
   *                                   also be specified, and this value must be
   *                                   greater than or equal to the minimum lock
   *                                   timeout.  If this is {@code null}, then
   *                                   the server will determine the database
   *                                   lock timeout settings to use.
   * @param  returnResponseControl     Indicates whether to return a response
   *                                   control with transaction-related
   *                                   information collected over the course of
   *                                   processing the associated operation.
   */
  public TransactionSettingsRequestControl(final boolean isCritical,
       @Nullable final String transactionName,
       @Nullable final TransactionSettingsCommitDurability commitDurability,
       @Nullable final TransactionSettingsBackendLockBehavior
            backendLockBehavior,
       @Nullable final Long backendLockTimeoutMillis,
       @Nullable final Integer retryAttempts,
       @Nullable final Long minTxnLockTimeoutMillis,
       @Nullable final Long maxTxnLockTimeoutMillis,
       final boolean returnResponseControl)
  {
    super(TRANSACTION_SETTINGS_REQUEST_OID, isCritical,
         encodeValue(transactionName, commitDurability, backendLockBehavior,
              backendLockTimeoutMillis, retryAttempts, minTxnLockTimeoutMillis,
              maxTxnLockTimeoutMillis, returnResponseControl));

    this.transactionName          = transactionName;
    this.commitDurability         = commitDurability;
    this.backendLockBehavior      = backendLockBehavior;
    this.backendLockTimeoutMillis = backendLockTimeoutMillis;
    this.minTxnLockTimeoutMillis  = minTxnLockTimeoutMillis;
    this.maxTxnLockTimeoutMillis  = maxTxnLockTimeoutMillis;
    this.retryAttempts            = retryAttempts;
    this.returnResponseControl    = returnResponseControl;
  }



  /**
   * Creates a new transaction settings request control that is decoded from the
   * provided generic control.
   *
   * @param  c  The generic control to decode as a transaction settings request
   *            control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the provided control as a transaction
   *                         settings request control.
   */
  public TransactionSettingsRequestControl(@NotNull final Control c)
         throws LDAPException
  {
    super(c);

    final ASN1OctetString value = c.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_TXN_SETTINGS_REQUEST_MISSING_VALUE.get());
    }

    try
    {
      boolean                                responseControl   = false;
      Integer                                numRetries        = null;
      Long                                   backendTimeout    = null;
      Long                                   maxTxnLockTimeout = null;
      Long                                   minTxnLockTimeout = null;
      String                                 txnName           = null;
      TransactionSettingsCommitDurability    durability        = null;
      TransactionSettingsBackendLockBehavior lockBehavior      = null;

      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(value.getValue()).elements())
      {
        switch (e.getType())
        {
          case TYPE_TXN_NAME:
            txnName = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;

          case TYPE_COMMIT_DURABILITY:
            durability = TransactionSettingsCommitDurability.valueOf(
                 ASN1Enumerated.decodeAsEnumerated(e).intValue());
            if (durability == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_TXN_SETTINGS_REQUEST_UNKNOWN_DURABILITY.get(
                        ASN1Enumerated.decodeAsEnumerated(e).intValue()));
            }
            break;

          case TYPE_BACKEND_LOCK_BEHAVIOR:
            lockBehavior = TransactionSettingsBackendLockBehavior.valueOf(
                 ASN1Enumerated.decodeAsEnumerated(e).intValue());
            if (lockBehavior == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_TXN_SETTINGS_REQUEST_UNKNOWN_LOCK_BEHAVIOR.get(
                        ASN1Enumerated.decodeAsEnumerated(e).intValue()));
            }
            break;

          case TYPE_BACKEND_LOCK_TIMEOUT:
            backendTimeout = ASN1Long.decodeAsLong(e).longValue();
            if (backendTimeout < 0L)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_TXN_SETTINGS_REQUEST_INVALID_BACKEND_LOCK_TIMEOUT.get(
                        backendTimeout));
            }
            break;

          case TYPE_RETRY_ATTEMPTS:
            numRetries = ASN1Integer.decodeAsInteger(e).intValue();
            if (numRetries < 0)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_TXN_SETTINGS_REQUEST_INVALID_RETRY_ATTEMPTS.get(
                        numRetries));
            }
            break;

          case TYPE_TXN_LOCK_TIMEOUT:
            final ASN1Element[] timeoutElements =
                 ASN1Sequence.decodeAsSequence(e).elements();
            minTxnLockTimeout =
                 ASN1Long.decodeAsLong(timeoutElements[0]).longValue();
            maxTxnLockTimeout =
                 ASN1Long.decodeAsLong(timeoutElements[1]).longValue();
            if (minTxnLockTimeout < 0)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_TXN_SETTINGS_REQUEST_INVALID_MIN_TXN_LOCK_TIMEOUT.get(
                        minTxnLockTimeout));
            }
            if (maxTxnLockTimeout < minTxnLockTimeout)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_TXN_SETTINGS_REQUEST_INVALID_MAX_TXN_LOCK_TIMEOUT.get(
                        maxTxnLockTimeout, minTxnLockTimeout));
            }
            break;

          case TYPE_RETURN_RESPONSE_CONTROL:
            responseControl = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_TXN_SETTINGS_REQUEST_UNRECOGNIZED_ELEMENT_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }

      transactionName          = txnName;
      commitDurability         = durability;
      backendLockBehavior      = lockBehavior;
      backendLockTimeoutMillis = backendTimeout;
      minTxnLockTimeoutMillis  = minTxnLockTimeout;
      maxTxnLockTimeoutMillis  = maxTxnLockTimeout;
      retryAttempts            = numRetries;
      returnResponseControl    = responseControl;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_TXN_SETTINGS_REQUEST_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into a form suitable for use as the value
   * of this ASN.1 element.
   *
   * @param  transactionName           The name to use for the transaction.  It
   *                                   may be {@code null} if no
   *                                   client-specified transaction name is
   *                                   needed.  If a transaction name is
   *                                   provided, it will be used purely for
   *                                   informational and/or troubleshooting
   *                                   purposes.
   * @param  commitDurability          The durability level that should be used
   *                                   when committing the associated
   *                                   transaction.  It may be {@code null} if
   *                                   the server-default durability level
   *                                   should be used.
   * @param  backendLockBehavior       The behavior that should be used with
   *                                   regard to acquiring an exclusive lock for
   *                                   processing in the target backend.  It may
   *                                   be {@code null} if the server-default
   *                                   backend lock behavior should be used.
   * @param  backendLockTimeoutMillis  The maximum length of time in
   *                                   milliseconds to spend attempting to
   *                                   acquire an exclusive backend lock if it
   *                                   is needed during any part of the
   *                                   processing.  A value that of zero
   *                                   indicates that no timeout should be
   *                                   enforced.  It may be {@code null} if the
   *                                   server will determine the backend lock
   *                                   timeout that should be used.
   * @param  retryAttempts             The number of times to retry the
   *                                   associated operations in a new
   *                                   transaction if the initial attempt fails.
   *                                   If this is {@code null}, then the server
   *                                   will determine the number of retry
   *                                   attempts to make.  Note that depending on
   *                                   the backend lock behavior, the server may
   *                                   make one additional retry attempt if
   *                                   necessary after acquiring an exclusive
   *                                   backend lock.
   * @param  minTxnLockTimeoutMillis   The minimum database lock timeout that
   *                                   should be used for the associated
   *                                   transaction.  If this is specified, then
   *                                   the first attempt will use this lock
   *                                   timeout, and subsequent attempts will use
   *                                   a timeout value between this and the
   *                                   maximum database lock timeout (which must
   *                                   also be specified).  If this is
   *                                   {@code null}, then the server will
   *                                   determine the database lock timeout
   *                                   settings to use.
   * @param  maxTxnLockTimeoutMillis   The maximum database lock timeout that
   *                                   should be used for the associated
   *                                   transaction.  If this is specified, then
   *                                   the minimum database lock timeout must
   *                                   also be specified, and this value must be
   *                                   greater than or equal to the minimum lock
   *                                   timeout.  If this is {@code null}, then
   *                                   the server will determine the database
   *                                   lock timeout settings to use.
   * @param  returnResponseControl     Indicates whether to return a response
   *                                   control with transaction-related
   *                                   information collected over the course of
   *                                   processing the associated operation.
   *
   * @return  The encoded value to use for the control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
       @Nullable final String transactionName,
       @Nullable final TransactionSettingsCommitDurability commitDurability,
       @Nullable final TransactionSettingsBackendLockBehavior
            backendLockBehavior,
       @Nullable final Long backendLockTimeoutMillis,
       @Nullable final Integer retryAttempts,
       @Nullable final Long minTxnLockTimeoutMillis,
       @Nullable final Long maxTxnLockTimeoutMillis,
       final boolean returnResponseControl)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(7);

    if (transactionName != null)
    {
      elements.add(new ASN1OctetString(TYPE_TXN_NAME, transactionName));
    }

    if (commitDurability != null)
    {
      elements.add(new ASN1Enumerated(TYPE_COMMIT_DURABILITY,
           commitDurability.intValue()));
    }

    if (backendLockBehavior != null)
    {
      elements.add(new ASN1Enumerated(TYPE_BACKEND_LOCK_BEHAVIOR,
           backendLockBehavior.intValue()));
    }

    if (backendLockTimeoutMillis != null)
    {
      Validator.ensureTrue((backendLockTimeoutMillis >= 0L),
           "If a backend lock timeout is specified, then it must be greater " +
                "than or equal to zero.");
      elements.add(new ASN1Long(TYPE_BACKEND_LOCK_TIMEOUT,
           backendLockTimeoutMillis));
    }

    if (retryAttempts != null)
    {
      Validator.ensureTrue((retryAttempts >= 0),
           "If specified, the number of retry attempts must be greater than " +
                "or equal to zero.");

      elements.add(new ASN1Integer(TYPE_RETRY_ATTEMPTS, retryAttempts));
    }

    if (minTxnLockTimeoutMillis != null)
    {
      Validator.ensureTrue((maxTxnLockTimeoutMillis != null),
           "If a minimum transaction lock timeout is specified, then a " +
                "maximum transaction lock timeout must also be specified.");
      Validator.ensureTrue((minTxnLockTimeoutMillis > 0),
           "If a minimum transaction lock timeout is specified, then it must " +
                "be greater than zero.");
      Validator.ensureTrue((maxTxnLockTimeoutMillis >= minTxnLockTimeoutMillis),
           "If a minimum transaction lock timeout is specified, then it must " +
                "be less than or equal to the minimum transaction lock " +
                "timeout.");
      elements.add(new ASN1Sequence(TYPE_TXN_LOCK_TIMEOUT,
           new ASN1Long(minTxnLockTimeoutMillis),
           new ASN1Long(maxTxnLockTimeoutMillis)));
    }
    else
    {
      Validator.ensureTrue((maxTxnLockTimeoutMillis == null),
           "If a maximum transaction lock timeout is specified, then a " +
                "minimum transaction lock timeout must also be specified.");
    }

    if (returnResponseControl)
    {
      elements.add(new ASN1Boolean(TYPE_RETURN_RESPONSE_CONTROL, true));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the name to assign to the associated transaction, if specified.
   *
   * @return  The name to assign to the associated transaction, or {@code null}
   *          if none has been specified.
   */
  @Nullable()
  public String getTransactionName()
  {
    return transactionName;
  }



  /**
   * Retrieves the commit durability that should be used for the associated
   * transaction, if specified.
   *
   * @return  The commit durability that should be used for the associated
   *          transaction, or {@code null} if none has been specified and the
   *          server should determine the commit durability.
   */
  @Nullable()
  public TransactionSettingsCommitDurability getCommitDurability()
  {
    return commitDurability;
  }



  /**
   * Retrieves the backend lock behavior that should be used for the associated
   * transaction, if specified.
   *
   * @return  The backend lock behavior that should be used for the associated
   *          transaction, or {@code null} if none has been specified and the
   *          server should determine the backend lock behavior.
   */
  @Nullable()
  public TransactionSettingsBackendLockBehavior getBackendLockBehavior()
  {
    return backendLockBehavior;
  }



  /**
   * Retrieves the backend lock timeout (in milliseconds) that should be used
   * for the associated transaction, if specified.
   *
   * @return  The backend lock timeout (in milliseconds) that should be used for
   *          the associated transaction, or {@code null} if none has been
   *          specified and the server should determine the backend lock
   *          timeout.
   */
  @Nullable()
  public Long getBackendLockTimeoutMillis()
  {
    return backendLockTimeoutMillis;
  }



  /**
   * Retrieves the maximum number of times that the transaction may be retried
   * if the initial attempt fails due to a lock conflict, if specified.
   *
   * @return  The maximum number of times that the transaction may be retried if
   *          the initial attempt fails due to a lock conflict, or {@code null}
   *          if none has been specified and the server should determine the
   *          number of retry attempts.
   */
  @Nullable()
  public Integer getRetryAttempts()
  {
    return retryAttempts;
  }



  /**
   * Retrieves the minimum transaction lock timeout (in milliseconds) that
   * should be used for the associated transaction, if specified.  This is the
   * timeout value that will be used for the first attempt.  Any subsequent
   * attempts will have a lock timeout that is between the minimum and maximum
   * timeout value.
   *
   * @return  The minimum lock timeout (in milliseconds) that should
   *          be used for the associated transaction, or {@code null} if none
   *          has been specified and the server should determine the minimum
   *          transaction lock timeout.
   */
  @Nullable()
  public Long getMinTxnLockTimeoutMillis()
  {
    return minTxnLockTimeoutMillis;
  }



  /**
   * Retrieves the maximum transaction lock timeout (in milliseconds) that
   * should be used for the associated transaction, if specified.  The timeout
   * to be used for any retries will be between the minimum and maximum lock
   * timeout values.
   *
   * @return  The maximum lock timeout (in milliseconds) that should
   *          be used for the associated transaction, or {@code null} if none
   *          has been specified and the server should determine the maximum
   *          transaction lock timeout.
   */
  @Nullable()
  public Long getMaxTxnLockTimeoutMillis()
  {
    return maxTxnLockTimeoutMillis;
  }



  /**
   * Indicates whether to return a response control with transaction-related
   * information collected over the course of processing the associated
   * operation.
   *
   * @return  {@code true} if the server should return a response control with
   *          transaction-related information, or {@code false} if not.
   */
  public boolean returnResponseControl()
  {
    return returnResponseControl;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_TXN_SETTINGS_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("TransactionSettingsRequestControl(isCritical=");
    buffer.append(isCritical());

    if (transactionName != null)
    {
      buffer.append(", transactionName='");
      buffer.append(transactionName);
      buffer.append('\'');
    }

    if (commitDurability != null)
    {
      buffer.append(", commitDurability='");
      buffer.append(commitDurability.name());
      buffer.append('\'');
    }

    if (backendLockBehavior != null)
    {
      buffer.append(", backendLockBehavior='");
      buffer.append(backendLockBehavior.name());
      buffer.append('\'');
    }

    if (backendLockTimeoutMillis != null)
    {
      buffer.append(", backendLockTimeoutMillis=");
      buffer.append(backendLockTimeoutMillis);
    }

    if (retryAttempts != null)
    {
      buffer.append(", retryAttempts=");
      buffer.append(retryAttempts);
    }

    if (minTxnLockTimeoutMillis != null)
    {
      buffer.append(", minTxnLockTimeoutMillis=");
      buffer.append(minTxnLockTimeoutMillis);
    }

    if (maxTxnLockTimeoutMillis != null)
    {
      buffer.append(", maxTxnLockTimeoutMillis=");
      buffer.append(maxTxnLockTimeoutMillis);
    }

    buffer.append(", returnResponseControl=");
    buffer.append(returnResponseControl);

    buffer.append(')');
  }
}
