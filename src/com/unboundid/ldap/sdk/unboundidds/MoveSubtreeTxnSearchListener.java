/*
 * Copyright 2012-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IgnoreNoUserModificationRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            InteractiveTransactionSpecificationRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            InteractiveTransactionSpecificationResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.util.Debug;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides a search result listener that will be used by the
 * {@link MoveSubtree#moveEntryWithInteractiveTransaction} method.  It will
 * accept entries identified in the source server and add them to the target
 * server.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class MoveSubtreeTxnSearchListener
      implements SearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5725895630679439468L;



  // Indicates whether the target transaction should be considered valid.
  private final AtomicBoolean targetTxnValid;

  // The counter for the number of entries added to the target server.
  private final AtomicInteger entriesAddedToTarget;

  // The counter for the number of entries read from the source server.
  private final AtomicInteger entriesReadFromSource;

  // A reference to the result code for move subtree processing.
  private final AtomicReference<ResultCode> resultCode;

  // The set of controls to include in add requests to the target server.
  private final Control[] addControls;

  // An LDAP connection that may be used to communicate with the target server.
  private final LDAPConnection targetConnection;

  // A listener that should be used to perform any processing before and after
  // add operations in the target server.
  private final MoveSubtreeListener moveListener;

  // A buffer to which any error messages encountered should be appended.
  private final StringBuilder errorMessage;

  // The DNs of the entries read from the source server.
  private final TreeSet<DN> sourceEntryDNs;



  /**
   * Creates a new move subtree transaction search listener with the provided
   * information.
   *
   * @param  targetConnection       An LDAP connection that may be used to
   *                                communicate with the target server.
   * @param  resultCode             A reference to the result code for move
   *                                subtree processing.
   * @param  errorMessage           A buffer to which information should be
   *                                appended about any errors encountered.
   * @param  entriesReadFromSource  A counter for the number of entries read
   *                                from the source server.
   * @param  entriesAddedToTarget   A counter for the number of entries added to
   *                                the target server.
   * @param  sourceEntryDNs         A set that should be used to hold the DNs
   *                                of entries read from the source server.
   * @param  targetTxnControl       The interactive transaction specification
   *                                control that should be included in requests
   *                                to the target server.
   * @param  opPurposeControl       The operation purpose request control to
   *                                include in all requests.
   * @param  moveListener           A move subtree listener that may be used to
   *                                perform any additional processing before and
   *                                after add operations in the target server.
   *                                It may be {@code null} if no move listener
   *                                is required.
   */
  MoveSubtreeTxnSearchListener(final LDAPConnection targetConnection,
       final AtomicReference<ResultCode> resultCode,
       final StringBuilder errorMessage,
       final AtomicInteger entriesReadFromSource,
       final AtomicInteger entriesAddedToTarget,
       final TreeSet<DN> sourceEntryDNs,
       final InteractiveTransactionSpecificationRequestControl targetTxnControl,
       final OperationPurposeRequestControl opPurposeControl,
       final MoveSubtreeListener moveListener)
  {
    this.targetConnection      = targetConnection;
    this.resultCode            = resultCode;
    this.errorMessage          = errorMessage;
    this.entriesReadFromSource = entriesReadFromSource;
    this.entriesAddedToTarget  = entriesAddedToTarget;
    this.sourceEntryDNs        = sourceEntryDNs;
    this.moveListener          = moveListener;

    targetTxnValid = new AtomicBoolean(true);

    if (opPurposeControl == null)
    {
      addControls = new Control[]
      {
        targetTxnControl,
        new IgnoreNoUserModificationRequestControl()
      };
    }
    else
    {
      addControls = new Control[]
      {
        targetTxnControl,
        new IgnoreNoUserModificationRequestControl(),
        opPurposeControl
      };
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
    // Increment the number of entries read from the source server and add its
    // DN to the source DN set.
    entriesReadFromSource.incrementAndGet();
    try
    {
      sourceEntryDNs.add(searchEntry.getParsedDN());
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      resultCode.compareAndSet(null, le.getResultCode());
      MoveSubtree.append(
           ERR_MOVE_SUBTREE_TXN_LISTENER_CANNOT_PARSE_DN.get(
                searchEntry.getDN(), StaticUtils.getExceptionMessage(le)),
           errorMessage);
      return;
    }


    // If any errors have been encountered in processing, then don't do anything
    // else.
    if (errorMessage.length() > 0)
    {
      return;
    }


    // If there is a move subtree listener, then invoke its pre-add processing.
    final ReadOnlyEntry entry;
    if (moveListener == null)
    {
      entry = searchEntry;
    }
    else
    {
      try
      {
        entry = moveListener.doPreAddProcessing(searchEntry);

        if (entry == null)
        {
          // This entry should not be included in the move.
          return;
        }

        if (! DN.equals(entry.getDN(), searchEntry.getDN()))
        {
          resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
          MoveSubtree.append(
               ERR_MOVE_SUBTREE_TXN_LISTENER_PRE_ADD_DN_ALTERED.get(
                    entry.getDN(), searchEntry.getDN()),
               errorMessage);
          return;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
        MoveSubtree.append(
             ERR_MOVE_SUBTREE_TXN_LISTENER_PRE_ADD_FAILURE.get(
                  searchEntry.getDN(), StaticUtils.getExceptionMessage(e)),
             errorMessage);
        return;
      }
    }


    // Generate an add request to add the entry to the target server.
    LDAPResult addResult;
    try
    {
      addResult = targetConnection.add(new AddRequest(entry, addControls));
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      addResult = le.toLDAPResult();
    }

    if (addResult.getResultCode() == ResultCode.SUCCESS)
    {
      entriesAddedToTarget.incrementAndGet();
    }
    else
    {
      resultCode.compareAndSet(null, addResult.getResultCode());
      MoveSubtree.append(
           ERR_MOVE_SUBTREE_TXN_LISTENER_ADD_FAILURE.get(
                searchEntry.getDN(), addResult.getDiagnosticMessage()),
           errorMessage);

      try
      {
        final InteractiveTransactionSpecificationResponseControl txnResult =
             InteractiveTransactionSpecificationResponseControl.get(addResult);
        if ((txnResult != null) && (! txnResult.transactionValid()))
        {
          targetTxnValid.set(false);
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
      }

      return;
    }

    try
    {
      final InteractiveTransactionSpecificationResponseControl txnResult =
           InteractiveTransactionSpecificationResponseControl.get(addResult);
      if ((txnResult != null) && (! txnResult.transactionValid()))
      {
        targetTxnValid.set(false);
        resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
        MoveSubtree.append(
             ERR_MOVE_SUBTREE_TXN_LISTENER_TXN_NO_LONGER_VALID.get(
                  searchEntry.getDN()),
             errorMessage);
        return;
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      resultCode.compareAndSet(null, le.getResultCode());
      MoveSubtree.append(
           ERR_MOVE_SUBTREE_TXN_LISTENER_CANNOT_DECODE_TXN_CONTROL.get(
                searchEntry.getDN(), StaticUtils.getExceptionMessage(le)),
           errorMessage);
      return;
    }


    // If there is a move subtree listener, then invoke its post-add processing.
    if (moveListener != null)
    {
      try
      {
        moveListener.doPostAddProcessing(entry);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
        MoveSubtree.append(
             ERR_MOVE_SUBTREE_TXN_LISTENER_POST_ADD_FAILURE.get(
                  searchEntry.getDN(), StaticUtils.getExceptionMessage(e)),
             errorMessage);
        return;
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    // Don't do anything if we've already encountered one or more errors.
    if (errorMessage.length() > 0)
    {
      return;
    }

    MoveSubtree.append(
         ERR_MOVE_SUBTREE_TXN_LISTENER_REFERENCE_RETURNED.get(
              StaticUtils.concatenateStrings(
                   searchReference.getReferralURLs())),
         errorMessage);
  }



  /**
   * Indicates whether the target transaction is still believed to be valid.
   *
   * @return  {@code true} if the target connection is still believed to be
   *          valid, or {@code false} if not.
   */
  boolean targetTransactionValid()
  {
    return targetTxnValid.get();
  }
}
