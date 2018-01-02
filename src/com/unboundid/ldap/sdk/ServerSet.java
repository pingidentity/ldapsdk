/*
 * Copyright 2008-2018 Ping Identity Corporation
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



import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;



/**
 * This class defines an API that can be used to select between multiple
 * directory servers when establishing a connection.  Implementations are free
 * to use any kind of logic that they desire when selecting the server to which
 * the connection is to be established.  They may also support the use of
 * health checks to determine whether the created connections are suitable for
 * use.
 * <BR><BR>
 * Implementations MUST be threadsafe to allow for multiple concurrent attempts
 * to establish new connections.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class ServerSet
{
  /**
   * Creates a new instance of this server set.
   */
  protected ServerSet()
  {
    // No implementation is required.
  }



  /**
   * Attempts to establish a connection to one of the directory servers in this
   * server set.  The connection should be established but unauthenticated.  The
   * caller may determine the server to which the connection is established
   * using the {@link LDAPConnection#getConnectedAddress} and
   * {@link LDAPConnection#getConnectedPort} methods.
   *
   * @return  An {@code LDAPConnection} object that is established to one of the
   *          servers in this server set.
   *
   * @throws  LDAPException  If it is not possible to establish a connection to
   *                         any of the servers in this server set.
   */
  public abstract LDAPConnection getConnection()
         throws LDAPException;



  /**
   * Attempts to establish a connection to one of the directory servers in this
   * server set, using the provided health check to further validate the
   * connection.  The connection should be established but unauthenticated.
   * The caller may determine the server to which the connection is established
   * using the {@link LDAPConnection#getConnectedAddress} and
   * {@link LDAPConnection#getConnectedPort} methods.
   *
   * @param  healthCheck  The health check to use to make the determination, or
   *                      {@code null} if no additional health check should be
   *                      performed.
   *
   * @return  An {@code LDAPConnection} object that is established to one of the
   *          servers in this server set.
   *
   * @throws  LDAPException  If it is not possible to establish a connection to
   *                         any of the servers in this server set.
   */
  public LDAPConnection getConnection(
                             final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    final LDAPConnection c = getConnection();

    if (healthCheck != null)
    {
      try
      {
        healthCheck.ensureNewConnectionValid(c);
      }
      catch (final LDAPException le)
      {
        debugException(le);
        c.close();
        throw le;
      }
    }

    return c;
  }



  /**
   * Retrieves a string representation of this server set.
   *
   * @return  A string representation of this server set.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this server set to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ServerSet(className=");
    buffer.append(getClass().getName());
    buffer.append(')');
  }
}
