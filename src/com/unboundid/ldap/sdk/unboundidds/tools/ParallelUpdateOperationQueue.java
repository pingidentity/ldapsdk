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



import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;



/**
 * This class provides a data structure that will be used to hold the operations
 * to process by the parallel-update tool.  The thread reading change records
 * from the LDIF file will populate this queue, and modify threads will pull
 * entries out.  It will attempt to maintain a sane ordering for the operations
 * in order to resolve any dependencies that may exist between operations.
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
final class ParallelUpdateOperationQueue
{
  // Indicates whether the end of the LDIF has been reached.
  private boolean endOfLDIF;

  // The map that will hold the DNs of the change records currently being
  // processed.
  @NotNull private final HashSet<DN> activeChanges;

  // The capacity for this queue.
  private final int capacity;

  // The current size of the queue.
  private int size;

  // The map that will hold the operations to be processed.
  @NotNull private final LinkedList<LDIFChangeRecord> opQueue;

  // The lock that will be used to provide thread safety for the queue.
  @NotNull private final Object queueLock;

  // The parallel update instance with which this queue is associated.
  @NotNull private final ParallelUpdate parallelUpdate;



  /**
   * Creates a new instance of this operation queue.
   *
   * @param  parallelUpdate  The parallel update instance with which this queue
   *                         is associated.
   * @param  numThreads      The number of threads expected to access this
   *                         queue.
   * @param  capacity        The maximum capacity to use for the queue.
   */
  ParallelUpdateOperationQueue(
       @NotNull final ParallelUpdate parallelUpdate,
       final int numThreads,
       final int capacity)
  {
    this.parallelUpdate = parallelUpdate;
    this.capacity       = capacity;

    endOfLDIF     = false;
    activeChanges = new HashSet<>(numThreads);
    opQueue       = new LinkedList<>();
    queueLock     = new Object();
    size          = 0;
  }



  /**
   * Adds the provided LDIF change record to this queue.  This method will block
   * if the queue is currently at its capacity.
   *
   * @param  changeRecord  The change record to be added to this queue.
   *
   * @throws  InterruptedException  If the thread is interrupted while waiting
   *                                for available capacity in the queue.
   */
  void addChangeRecord(@NotNull final LDIFChangeRecord changeRecord)
       throws InterruptedException
  {
    // First, make sure that we can parse the DN of the change record.  If not,
    // then reject the change record.
    try
    {
      changeRecord.getParsedDN();
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      parallelUpdate.reject(changeRecord, e);
      return;
    }

    synchronized (queueLock)
    {
      while (size >= capacity)
      {
        queueLock.wait(1000L);
      }

      opQueue.add(changeRecord);
      size++;
      queueLock.notifyAll();
    }
  }



  /**
   * Retrieves the next LDIF change record to be processed.  This method will
   * block if the queue is currently empty but the end of the LDIF file has not
   * yet been reached, or if all of the operations currently held in the queue
   * are dependent upon an operation in progress.
   *
   * @param  completedDNs  The DNs of the entries targeted by the last change.
   *                       It should be empty for the first request processed by
   *                       a thread, should have a single element if the last
   *                       change was an add, delete, or modify, and should have
   *                       two elements if the last change was a modify DN.
   *
   * @return  The next LDIF change record to be processed, or {@code null} if
   *          there are no more change records to process and the end of the
   *          LDIF file has been reached.
   */
  @Nullable()
  LDIFChangeRecord getChangeRecord(@NotNull final DN... completedDNs)
  {
    synchronized (queueLock)
    {
      for (final DN dn : completedDNs)
      {
        activeChanges.remove(dn);
      }

      while (! (endOfLDIF && opQueue.isEmpty()))
      {
        if (opQueue.isEmpty())
        {
          try
          {
            queueLock.wait(1000L);
          }
          catch (final InterruptedException e)
          {
            Debug.debugException(e);
          }
          continue;
        }

        final Iterator<LDIFChangeRecord> iterator = opQueue.iterator();
iteratorLoop:
        while (iterator.hasNext())
        {
          final LDIFChangeRecord r = iterator.next();

          // Get the parsed target DN for the change record.
          final DN targetDN;
          try
          {
            targetDN = r.getParsedDN();
          }
          catch (final LDAPException e)
          {
            // This should never happen, but if it does then reject the change.
            parallelUpdate.reject(r, e);
            iterator.remove();
            size--;
            continue;
          }

          // Make sure that we are not currently processing any operation that
          // involves the entry or any of its ancestors.  If it is a delete,
          // then make sure that we are not processing any operation that
          // involves any of its descendants.  If it is a modify DN operation,
          // then we need to ensure that neither the current DN nor the new DN
          // conflict with any active operations.
          if (! activeChanges.isEmpty())
          {
            for (final DN activeDN : activeChanges)
            {
              if (activeDN.isAncestorOf(targetDN, true))
              {
                continue iteratorLoop;
              }
            }

            if (r instanceof LDIFDeleteChangeRecord)
            {
              for (final DN activeDN : activeChanges)
              {
                if (activeDN.isDescendantOf(targetDN, false))
                {
                  continue iteratorLoop;
                }
              }
            }
            else if (r instanceof LDIFModifyDNChangeRecord)
            {
              final LDIFModifyDNChangeRecord modDNRecord =
                   (LDIFModifyDNChangeRecord) r;

              final DN newDN;
              try
              {
                newDN = modDNRecord.getNewDN();
              }
              catch (final LDAPException e)
              {
                // We could not parse the new DN, so reject the change.
                parallelUpdate.reject(r, e);
                iterator.remove();
                size--;
                continue iteratorLoop;
              }

              for (final DN activeDN : activeChanges)
              {
                if (activeDN.isDescendantOf(targetDN, false) ||
                    activeDN.isAncestorOf(newDN, true) ||
                    activeDN.isDescendantOf(newDN, false))
                {
                  continue iteratorLoop;
                }
              }

              // At this point, we know that the modify DN will be processed so
              // reserve the new DN as well.  The target DN will be reserved
              // below.
              activeChanges.add(newDN);
            }
          }

          // At this point, the change will be processed so remove it from the
          // queue and add it to the list of active changes.  Also, notify any
          // threads that might be waiting on the queue lock in case
          // addChangeRecord is waiting on available space.
          activeChanges.add(targetDN);
          iterator.remove();
          size--;
          queueLock.notifyAll();
          return r;
        }

        // If we've gotten here, then the queue isn't empty, but all of the
        // operations contained in it are dependent upon operations that are
        // actively being processed.  In that case, wait for an operation to
        // complete before trying again.
        try
        {
          queueLock.wait(1000L);
        }
        catch (final InterruptedException e)
        {
          Debug.debugException(e);
        }
      }
    }

    // If we've gotten here, then there is no more data to be processed.
    return null;
  }



  /**
   * Blocks until the operation queue is idle (i.e., the operation queue is
   * empty and there are no active changes).
   */
  public void waitUntilIdle()
  {
    synchronized (queueLock)
    {
      while (true)
      {
        if (opQueue.isEmpty() && activeChanges.isEmpty())
        {
          return;
        }

        try
        {
          queueLock.wait(1000L);
        }
        catch (final InterruptedException e)
        {
          Debug.debugException(e);
        }
      }
    }
  }



  /**
   * Indicates that the end of the LDIF has been reached and that no more data
   * will be added to the queue.
   */
  public void setEndOfLDIF()
  {
    synchronized (queueLock)
    {
      endOfLDIF = true;
      queueLock.notifyAll();
    }
  }
}
