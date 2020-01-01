/*
 * Copyright 2009-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2020 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.net.Socket;



/**
 * This class provides an implementation of an {@code LDAPSocketFactory} to use
 * for testing.
 */
public class TestLDAPSocketFactory
       implements LDAPSocketFactory
{
  /**
   * Creates a new instance of this socket factory.
   */
  public TestLDAPSocketFactory()
  {
    // No implementation required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Socket makeSocket(final String host, final int port)
         throws LDAPException
  {
    try
    {
      return new Socket(host, port);
    }
    catch (Exception e)
    {
      throw new LDAPException("Cannot create the socket",
                              LDAPException.CONNECT_ERROR);
    }
  }
}
