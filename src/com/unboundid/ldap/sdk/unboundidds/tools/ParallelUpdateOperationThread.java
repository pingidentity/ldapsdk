/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.unboundidds.controls.UndeleteRequestControl;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.util.Debug;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;



/**
 * This class implements a thread that may be used to process operations in
 * a directory server.  It will have its own connection to the Directory Server
 * and will loop, reading and applying changes until no more are available.
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
final class ParallelUpdateOperationThread
      extends Thread
{
  /**
   * The name of the attribute type that may be included in an add request that
   * represents an undelete to indicate the DN of the soft-deleted entry that
   * should be resurrected.
   */
  @NotNull private static final String ATTR_UNDELETE_FROM_DN =
       "ds-undelete-from-dn";



  // Indicates whether to allow add operations to be treated as undeletes.
  private final boolean allowUndelete;

  // The set of controls to include in all add requests.
  @NotNull private final Control[] addControls;

  // The set of controls to include in all delete requests.
  @NotNull private final Control[] deleteControls;

  // The set of controls to include in all modify requests.
  @NotNull private final Control[] modifyControls;

  // The set of controls to include in all modify DN requests.
  @NotNull private final Control[] modifyDNControls;

  // A rate limiter that will be used to control the rate at which operations
  // are attempted.
  @Nullable private final FixedRateBarrier rateLimiter;

  // The LDAP connection pool to use to communicate with the server.
  @NotNull private final LDAPConnectionPool connectionPool;

  // The operation queue used to retrieve the changes to process.
  @NotNull private final ParallelUpdateOperationQueue opQueue;

  // The parallel update tool instance with which this thread is associated.
  @NotNull private final ParallelUpdate parallelUpdate;



  /**
   * Creates a new operation thread with the provided information.
   *
   * @param  parallelUpdate    The parallel update program with which this
   *                           thread is associated.
   * @param  connectionPool    The connection pool to use to communicate with
   *                           the server.
   * @param  opQueue           The operation queue used to retrieve the changes
   *                           to process.
   * @param  threadNumber      The thread number for this thread, to use for
   *                           identification purposes.
   * @param  rateLimiter       A rate limiter that can be used to control the
   *                           rate at which operations are attempted.  It may
   *                           be {@code null} if no rate limiting is needed.
   * @param  addControls       The set of controls to include in all add
   *                           requests.  It must not be {@code null} but may be
   *                           empty.
   * @param  deleteControls    The set of controls to include in all delete
   *                           requests.  It must not be {@code null} but may be
   *                           empty.
   * @param  modifyControls    The set of controls to include in all modify
   *                           requests.  It must not be {@code null} but may be
   *                           empty.
   * @param  modifyDNControls  The set of controls to include in all modify DN
   *                           requests.  It must not be {@code null} but may be
   *                           empty.
   * @param  allowUndelete     Indicates whether to allow add operations to be
   *                           treated as undeletes.
   */
  ParallelUpdateOperationThread(
       @NotNull final ParallelUpdate parallelUpdate,
       @NotNull final LDAPConnectionPool connectionPool,
       @NotNull final ParallelUpdateOperationQueue opQueue,
       final int threadNumber,
       @Nullable final FixedRateBarrier rateLimiter,
       @NotNull final Control[] addControls,
       @NotNull final Control[] deleteControls,
       @NotNull final Control[] modifyControls,
       @NotNull final Control[] modifyDNControls,
       final boolean allowUndelete)
  {
    setName("Parallel Update Operation Thread " + threadNumber);

    this.parallelUpdate = parallelUpdate;
    this.connectionPool  = connectionPool;
    this.opQueue = opQueue;
    this.rateLimiter = rateLimiter;
    this.addControls = addControls;
    this.deleteControls = deleteControls;
    this.modifyControls = modifyControls;
    this.modifyDNControls = modifyDNControls;
    this.allowUndelete = allowUndelete;
  }



  /**
   * Operates in a loop, retrieving changes from the operation queue and
   * processing them.
   */
  @Override()
  public void run()
  {
    LDIFChangeRecord r = opQueue.getChangeRecord();

    // Various controls that might be present on the requests.
    final Control undeleteRequestControl = new UndeleteRequestControl();

    while (r != null)
    {
      if (rateLimiter != null)
      {
        rateLimiter.await();
      }

      DN parsedDN = null;
      DN parsedNewDN = null;
      final long startTime = System.currentTimeMillis();

      try
      {
        parsedDN = r.getParsedDN();
        if (r instanceof LDIFAddChangeRecord)
        {
          final AddRequest addRequest =
               ((LDIFAddChangeRecord) r).toAddRequest();
          addRequest.addControls(addControls);
          if (allowUndelete && addRequest.hasAttribute(ATTR_UNDELETE_FROM_DN))
          {
            addRequest.addControl(undeleteRequestControl);
          }
          connectionPool.add(addRequest);
          parallelUpdate.opCompletedSuccessfully(r,
               (System.currentTimeMillis() - startTime));
        }
        else if (r instanceof LDIFDeleteChangeRecord)
        {
          final DeleteRequest deleteRequest =
               ((LDIFDeleteChangeRecord) r).toDeleteRequest();
          deleteRequest.addControls(deleteControls);
          connectionPool.delete(deleteRequest);
          parallelUpdate.opCompletedSuccessfully(r,
               (System.currentTimeMillis() - startTime));
        }
        else if (r instanceof LDIFModifyChangeRecord)
        {
          final ModifyRequest modifyRequest =
               ((LDIFModifyChangeRecord) r).toModifyRequest();
          modifyRequest.addControls(modifyControls);
          connectionPool.modify(modifyRequest);
          parallelUpdate.opCompletedSuccessfully(r,
                                (System.currentTimeMillis() - startTime));
        }
        else if (r instanceof LDIFModifyDNChangeRecord)
        {
          final LDIFModifyDNChangeRecord modifyDNChangeRecord =
               (LDIFModifyDNChangeRecord) r;
          parsedNewDN = modifyDNChangeRecord.getNewDN();
          final ModifyDNRequest modifyDNRequest =
               modifyDNChangeRecord.toModifyDNRequest();
          modifyDNRequest.addControls(modifyDNControls);
          connectionPool.modifyDN(modifyDNRequest);
          parallelUpdate.opCompletedSuccessfully(r,
               (System.currentTimeMillis() - startTime));
        }
        else
        {
          // This should never happen.
          r.processChange(connectionPool);
          parallelUpdate.opCompletedSuccessfully(r,
               (System.currentTimeMillis() - startTime));
        }
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        parallelUpdate.opFailed(r, e,
             (System.currentTimeMillis() - startTime));
      }

      if (parsedNewDN == null)
      {
        r = opQueue.getChangeRecord(parsedDN);
      }
      else
      {
        r = opQueue.getChangeRecord(parsedDN, parsedNewDN);
      }
    }
  }
}
