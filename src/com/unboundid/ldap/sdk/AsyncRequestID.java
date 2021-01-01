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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class defines an object that provides information about a request that
 * was initiated asynchronously.  It may be used to abandon or cancel the
 * associated request.  This class also implements the
 * {@code java.util.concurrent.Future} interface, so it may be used in that
 * manner.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example initiates an asynchronous modify operation and then
 * attempts to abandon it:
 * <PRE>
 * Modification mod = new Modification(ModificationType.REPLACE,
 *      "description", "This is the new description.");
 * ModifyRequest modifyRequest =
 *      new ModifyRequest("dc=example,dc=com", mod);
 *
 * AsyncRequestID asyncRequestID =
 *      connection.asyncModify(modifyRequest, myAsyncResultListener);
 *
 * // Assume that we've waited a reasonable amount of time but the modify
 * // hasn't completed yet so we'll try to abandon it.
 *
 * connection.abandon(asyncRequestID);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AsyncRequestID
       implements Serializable, Future<LDAPResult>
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8244005138437962030L;



  // The queue used to receive the result for the associated operation.
  @NotNull private final ArrayBlockingQueue<LDAPResult> resultQueue;

  // A flag indicating whether a request has been made to cancel the operation.
  @NotNull private final AtomicBoolean cancelRequested;

  // The result for the associated operation.
  @NotNull private final AtomicReference<LDAPResult> result;

  // The message ID for the request message.
  private final int messageID;

  // The connection used to process the asynchronous operation.
  @NotNull private final LDAPConnection connection;

  // The timer task that will allow the associated request to be cancelled.
  @Nullable private volatile AsyncTimeoutTimerTask timerTask;



  /**
   * Creates a new async request ID with the provided message ID.
   *
   * @param  messageID   The message ID for the associated request.
   * @param  connection  The connection used to process the asynchronous
   *                     operation.
   */
  AsyncRequestID(final int messageID, @NotNull final LDAPConnection connection)
  {
    this.messageID  = messageID;
    this.connection = connection;

    resultQueue     = new ArrayBlockingQueue<>(1);
    cancelRequested = new AtomicBoolean(false);
    result          = new AtomicReference<>();
    timerTask       = null;
  }



  /**
   * Retrieves the message ID for the associated request.
   *
   * @return  The message ID for the associated request.
   */
  public int getMessageID()
  {
    return messageID;
  }



  /**
   * Attempts to cancel the associated asynchronous operation operation.  This
   * will cause an abandon request to be sent to the server for the associated
   * request, but because there is no response to an abandon operation then
   * there is no way that we can determine whether the operation was actually
   * abandoned.
   *
   * @param  mayInterruptIfRunning  Indicates whether to interrupt the thread
   *                                running the associated task.  This will be
   *                                ignored.
   *
   * @return  {@code true} if an abandon request was sent to cancel the
   *          associated operation, or {@code false} if it was not possible to
   *          send an abandon request because the operation has already
   *          completed, because an abandon request has already been sent, or
   *          because an error occurred while trying to send the cancel request.
   */
  @Override()
  public boolean cancel(final boolean mayInterruptIfRunning)
  {
    // If the operation has already completed, then we can't cancel it.
    if (isDone())
    {
      return false;
    }

    // Try to send a request to cancel the operation.
    try
    {
      cancelRequested.set(true);
      result.compareAndSet(null,
           new LDAPResult(messageID, ResultCode.USER_CANCELED,
                INFO_ASYNC_REQUEST_USER_CANCELED.get(), null,
                StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS));

      connection.abandon(this);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    return true;
  }



  /**
   * Indicates whether an attempt has been made to cancel the associated
   * operation before it completed.
   *
   * @return  {@code true} if an attempt was made to cancel the operation, or
   *          {@code false} if no cancel attempt was made, or if the operation
   *          completed before it could be canceled.
   */
  @Override()
  public boolean isCancelled()
  {
    return cancelRequested.get();
  }



  /**
   * Indicates whether the associated operation has completed, regardless of
   * whether it completed normally, completed with an error, or was canceled
   * before starting.
   *
   * @return  {@code true} if the associated operation has completed, or if an
   *          attempt has been made to cancel it, or {@code false} if the
   *          operation has not yet completed and no cancel attempt has been
   *          made.
   */
  @Override()
  public boolean isDone()
  {
    if (cancelRequested.get())
    {
      return true;
    }

    if (result.get() != null)
    {
      return true;
    }

    final LDAPResult newResult = resultQueue.poll();
    if (newResult != null)
    {
      result.set(newResult);
      return true;
    }

    return false;
  }



  /**
   * Attempts to get the result for the associated operation, waiting if
   * necessary for it to complete.  Note that this method will differ from the
   * behavior defined in the {@code java.util.concurrent.Future} API in that it
   * will not wait forever.  Rather, it will wait for no more than the length of
   * time specified as the maximum response time defined in the connection
   * options for the connection used to send the asynchronous request.  This is
   * necessary because the operation may have been abandoned or otherwise
   * interrupted, or the associated connection may have become invalidated, in
   * a way that the LDAP SDK cannot detect.
   *
   * @return  The result for the associated operation.  If the operation has
   *          been canceled, or if no result has been received within the
   *          response timeout period, then a generated response will be
   *          returned.
   *
   * @throws  InterruptedException  If the thread calling this method was
   *                                interrupted before a result was received.
   */
  @Override()
  @NotNull()
  public LDAPResult get()
         throws InterruptedException
  {
    final long maxWaitTime =
         connection.getConnectionOptions().getResponseTimeoutMillis();

    try
    {
      return get(maxWaitTime, TimeUnit.MILLISECONDS);
    }
    catch (final TimeoutException te)
    {
      Debug.debugException(te);
      return new LDAPResult(messageID, ResultCode.TIMEOUT, te.getMessage(),
           null, StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS);
    }
  }



  /**
   * Attempts to get the result for the associated operation, waiting if
   * necessary for up to the specified length of time for the operation to
   * complete.
   *
   * @param  timeout   The maximum length of time to wait for the response.
   * @param  timeUnit  The time unit for the provided {@code timeout} value.
   *
   * @return  The result for the associated operation.  If the operation has
   *          been canceled, then a generated response will be returned.
   *
   * @throws  InterruptedException  If the thread calling this method was
   *                                interrupted before a result was received.
   *
   * @throws  TimeoutException  If a timeout was encountered before the result
   *                            could be obtained.
   */
  @Override()
  @NotNull()
  public LDAPResult get(final long timeout, @NotNull final TimeUnit timeUnit)
         throws InterruptedException, TimeoutException
  {
    final LDAPResult newResult = resultQueue.poll();
    if (newResult != null)
    {
      result.set(newResult);
      return newResult;
    }

    final LDAPResult previousResult = result.get();
    if (previousResult != null)
    {
      return previousResult;
    }

    final LDAPResult resultAfterWaiting = resultQueue.poll(timeout, timeUnit);
    if (resultAfterWaiting == null)
    {
      final long timeoutMillis = timeUnit.toMillis(timeout);
      throw new TimeoutException(
           WARN_ASYNC_REQUEST_GET_TIMEOUT.get(timeoutMillis));
    }
    else
    {
      result.set(resultAfterWaiting);
      return resultAfterWaiting;
    }
  }



  /**
   * Sets the timer task that may be used to cancel this result after a period
   * of time.
   *
   * @param  timerTask  The timer task that may be used to cancel this result
   *                    after a period of time.  It may be {@code null} if no
   *                    timer task should be used.
   */
  void setTimerTask(@Nullable final AsyncTimeoutTimerTask timerTask)
  {
    this.timerTask = timerTask;
  }



  /**
   * Sets the result for the associated operation.
   *
   * @param  result  The result for the associated operation.  It must not be
   *                 {@code null}.
   */
  void setResult(@NotNull final LDAPResult result)
  {
    resultQueue.offer(result);

    final AsyncTimeoutTimerTask t = timerTask;
    if (t != null)
    {
      t.cancel();
      connection.getTimer().purge();
      timerTask = null;
    }
  }



  /**
   * Retrieves a hash code for this async request ID.
   *
   * @return  A hash code for this async request ID.
   */
  @Override()
  public int hashCode()
  {
    return messageID;
  }



  /**
   * Indicates whether the provided object is equal to this async request ID.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is equal to this async request
   *          ID, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (o instanceof AsyncRequestID)
    {
      return (((AsyncRequestID) o).messageID == messageID);
    }
    else
    {
      return false;
    }
  }



  /**
   * Retrieves a string representation of this async request ID.
   *
   * @return  A string representation of this async request ID.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return "AsyncRequestID(messageID=" + messageID + ')';
  }
}
