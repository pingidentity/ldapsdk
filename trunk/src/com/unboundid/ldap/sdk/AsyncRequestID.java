/*
 * Copyright 2008-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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

import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an object that provides information about a request that
 * was initiated asynchronously.  It may be used to abandon or cancel the
 * associated request.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example initiates an asynchronous modify operation and then
 * attempts to abandon it:
 * <PRE>
 *   Modification mod = new Modification(ModificationType.REPLACE,
 *        "description", "This is the new description.");
 *   ModifyRequest modifyRequest =
 *        new ModifyRequest("dc=example,dc=com", mod);
 *
 *   AsyncRequestID asyncRequestID =
 *        connection.asyncModify(modifyRequest, myAsyncResultListener);
 *
 *   // Assume that we've waited a reasonable amount of time but the modify
 *   // hasn't completed yet so we'll try to abandon it.
 *
 *   connection.abandon(asyncRequestID);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AsyncRequestID
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8244005138437962030L;



  // The message ID for the request message.
  private final int messageID;



  /**
   * Creates a new async request ID with the provided message ID.
   *
   * @param  messageID  The message ID for the associated request.
   */
  AsyncRequestID(final int messageID)
  {
    this.messageID = messageID;
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
  public boolean equals(final Object o)
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
  public String toString()
  {
    return "AsyncRequestID(messageID=" + messageID + ')';
  }
}
