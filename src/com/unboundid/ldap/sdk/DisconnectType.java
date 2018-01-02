/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This enum defines a set of disconnect types that may be used to provide
 * general information about the reason that an {@link LDAPConnection} was
 * disconnected.  Note that additional disconnect types may be added in the
 * future, so any decision made based on a disconnect type should account for
 * the possibility of previously-undefined disconnect types.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum DisconnectType
{
  /**
   * The connection was closed as a result of an unbind request sent by the
   * client.
   */
  UNBIND(INFO_DISCONNECT_TYPE_UNBIND.get(), ResultCode.LOCAL_ERROR),



  /**
   * The connection was closed at the request of the client, but without first
   * sending an unbind request.
   */
  CLOSED_WITHOUT_UNBIND(INFO_DISCONNECT_TYPE_CLOSED_WITHOUT_UNBIND.get(),
       ResultCode.LOCAL_ERROR),



  /**
   * The connection was closed because a bind performed as part of the
   * creation did not complete successfully.
   */
  BIND_FAILED(INFO_DISCONNECT_TYPE_BIND_FAILED.get(),
       ResultCode.CONNECT_ERROR),



  /**
   * The connection was closed because it is going to be re-established.
   */
  RECONNECT(INFO_DISCONNECT_TYPE_RECONNECT.get(), ResultCode.SERVER_DOWN),



  /**
   * The connection was closed because it had been a temporary connection
   * created for following a referral and was no longer needed.
   */
  REFERRAL(INFO_DISCONNECT_TYPE_REFERRAL.get(), ResultCode.LOCAL_ERROR),



  /**
   * The connection was closed by the server, and a notice of disconnection
   * unsolicited notification was provided.
   */
  SERVER_CLOSED_WITH_NOTICE(
       INFO_DISCONNECT_TYPE_SERVER_CLOSED_WITH_NOTICE.get(),
       ResultCode.SERVER_DOWN),



  /**
   * The connection was closed by the server without a notice of disconnection.
   */
  SERVER_CLOSED_WITHOUT_NOTICE(
       INFO_DISCONNECT_TYPE_SERVER_CLOSED_WITHOUT_NOTICE.get(),
       ResultCode.SERVER_DOWN),



  /**
   * The connection was closed because an I/O problem was encountered while
   * trying to communicate with the server.
   */
  IO_ERROR(INFO_DISCONNECT_TYPE_IO_ERROR.get(), ResultCode.SERVER_DOWN),



  /**
   * The connection was closed because an error occurred while trying to decode
   * data from the server.
   */
  DECODE_ERROR(INFO_DISCONNECT_TYPE_DECODE_ERROR.get(),
       ResultCode.DECODING_ERROR),



  /**
   * The connection was closed because an unexpected error occurred within the
   * LDAP SDK.
   */
  LOCAL_ERROR(INFO_DISCONNECT_TYPE_LOCAL_ERROR.get(), ResultCode.LOCAL_ERROR),



  /**
   * The connection was closed because a problem was encountered while
   * negotiating a security layer with the server.
   */
  SECURITY_PROBLEM(INFO_DISCONNECT_TYPE_SECURITY_PROBLEM.get(),
       ResultCode.LOCAL_ERROR),



  /**
   * The connection was closed because it was part of a connection pool that
   * was closed.
   */
  POOL_CLOSED(INFO_DISCONNECT_TYPE_POOL_CLOSED.get(), ResultCode.LOCAL_ERROR),



  /**
   * The connection was closed because it was part of a connection pool that
   * was being initialized and a failure occurred while attempting to create
   * another connection as part of the pool.
   */
  POOL_CREATION_FAILURE(INFO_DISCONNECT_TYPE_POOL_CREATION_FAILURE.get(),
       ResultCode.CONNECT_ERROR),



  /**
   * The connection was closed because it was part of a connection pool and had
   * been classified as defunct.
   */
  POOLED_CONNECTION_DEFUNCT(
       INFO_DISCONNECT_TYPE_POOLED_CONNECTION_DEFUNCT.get(),
       ResultCode.SERVER_DOWN),



  /**
   * The connection was closed because it was part of a connection pool and the
   * connection had been established for longer than the maximum connection
   * age for the pool.
   */
  POOLED_CONNECTION_EXPIRED(
       INFO_DISCONNECT_TYPE_POOLED_CONNECTION_EXPIRED.get(),
       ResultCode.LOCAL_ERROR),



  /**
   * The connection was closed because it was part of a connection pool and was
   * no longer needed.
   */
  POOLED_CONNECTION_UNNEEDED(
       INFO_DISCONNECT_TYPE_POOLED_CONNECTION_UNNEEDED.get(),
       ResultCode.LOCAL_ERROR),



  /**
   * The reason for the disconnect is not known.  This generally indicates a
   * problem with inappropriate instrumentation in the LDAP SDK.
   */
  UNKNOWN(INFO_DISCONNECT_TYPE_UNKNOWN.get(), ResultCode.LOCAL_ERROR),



  /**
   * The connection was closed by a finalizer in the LDAP SDK, which indicates
   * that it was not properly closed by the application that had been using
   * it.
   */
  CLOSED_BY_FINALIZER(INFO_DISCONNECT_TYPE_CLOSED_BY_FINALIZER.get(),
       ResultCode.LOCAL_ERROR),



  /**
   * The connection was closed for a reason that does not fit any other
   * defined disconnect type.
   */
  OTHER(INFO_DISCONNECT_TYPE_OTHER.get(), ResultCode.LOCAL_ERROR);



  // The result code most closely associated with this disconnect type.
  private final ResultCode resultCode;

  // A description for this disconnect type.
  private final String description;



  /**
   * Creates a new disconnect type with the specified description.
   *
   * @param  description  The description for this disconnect type.
   * @param  resultCode   The result code most closely associated with this
   *                      disconnect type.
   */
  DisconnectType(final String description, final ResultCode resultCode)
  {
    this.description = description;
    this.resultCode  = resultCode;
  }



  /**
   * Retrieves the description for this disconnect type.
   *
   * @return  The description for this disconnect type.
   */
  public String getDescription()
  {
    return description;
  }



  /**
   * Retrieves the result code most closely associated with this disconnect
   * type.
   *
   * @return  The result code most closely associated with this disconnect type.
   */
  public ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the disconnect type with the specified name.
   *
   * @param  name  The name of the disconnect type to retrieve.
   *
   * @return  The requested change type, or {@code null} if no such
   *          disconnect type is defined.
   */
  public static DisconnectType forName(final String name)
  {
    final String lowerName = toLowerCase(name);
    if (lowerName.equals("unbind"))
    {
      return UNBIND;
    }
    if (lowerName.equals("closed_without_unbind"))
    {
      return CLOSED_WITHOUT_UNBIND;
    }
    else if (lowerName.equals("bind_failed"))
    {
      return BIND_FAILED;
    }
    else if (lowerName.equals("reconnect"))
    {
      return RECONNECT;
    }
    else if (lowerName.equals("referral"))
    {
      return REFERRAL;
    }
    else if (lowerName.equals("server_closed_with_notice"))
    {
      return SERVER_CLOSED_WITH_NOTICE;
    }
    else if (lowerName.equals("server_closed_without_notice"))
    {
      return SERVER_CLOSED_WITHOUT_NOTICE;
    }
    else if (lowerName.equals("io_error"))
    {
      return IO_ERROR;
    }
    else if (lowerName.equals("decode_error"))
    {
      return DECODE_ERROR;
    }
    else if (lowerName.equals("local_error"))
    {
      return LOCAL_ERROR;
    }
    else if (lowerName.equals("security_problem"))
    {
      return SECURITY_PROBLEM;
    }
    else if (lowerName.equals("pool_closed"))
    {
      return POOL_CLOSED;
    }
    else if (lowerName.equals("pool_creation_failure"))
    {
      return POOL_CREATION_FAILURE;
    }
    else if (lowerName.equals("pooled_connection_defunct"))
    {
      return POOLED_CONNECTION_DEFUNCT;
    }
    else if (lowerName.equals("pooled_connection_expired"))
    {
      return POOLED_CONNECTION_EXPIRED;
    }
    else if (lowerName.equals("pooled_connection_unneeded"))
    {
      return POOLED_CONNECTION_UNNEEDED;
    }
    else if (lowerName.equals("unknown"))
    {
      return UNKNOWN;
    }
    else if (lowerName.equals("closed_by_finalizer"))
    {
      return CLOSED_BY_FINALIZER;
    }
    else if (lowerName.equals("other"))
    {
      return OTHER;
    }

    return null;
  }



  /**
   * Indicates whether the provided disconnect type is likely one that is
   * expected in some way.  This includes the following:
   * <UL>
   *   <LI>Connections closed by the application.</LI>
   *   <LI>Connections which are managed as part of a connection pool.</LI>
   *   <LI>Temporary connections created for following a referral.</LI>
   *   <LI>Connections which are being closed by the SDK so they can be
   *       re-established.</LI>
   *   <LI>Connections that were not properly closed by the application but are
   *       no longer in use and are being closed by a finalizer.</LI>
   * </UL>
   *
   * @param  disconnectType  The disconnect type for which to make the
   *                         determination.
   *
   * @return  {@code true} if the connection is one that can be classified as
   *          expected and there is likely nothing that a disconnect handler
   *          needs to do to handle it, or {@code false} if not.
   */
  public static boolean isExpected(final DisconnectType disconnectType)
  {
    switch (disconnectType)
    {
      case UNBIND:
      case CLOSED_WITHOUT_UNBIND:
      case RECONNECT:
      case REFERRAL:
      case POOL_CLOSED:
      case POOLED_CONNECTION_DEFUNCT:
      case POOLED_CONNECTION_EXPIRED:
      case POOLED_CONNECTION_UNNEEDED:
      case CLOSED_BY_FINALIZER:
        return true;
      default:
        return false;
    }
  }



  /**
   * Retrieves a string representation for this disconnect type.
   *
   * @return  A string representation for this disconnect type.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this disconnect type to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("DisconnectType(name='");
    buffer.append(name());
    buffer.append("', resultCode='");
    buffer.append(resultCode);
    buffer.append("', description='");
    buffer.append(description);
    buffer.append("')");
  }
}
