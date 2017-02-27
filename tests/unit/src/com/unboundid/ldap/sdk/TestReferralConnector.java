/*
 * Copyright 2008-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 UnboundID Corp.
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



/**
 * This class provides a simple referral connector that may be used for testing
 * purposes.  It will create unauthenticated connections.
 */
public class TestReferralConnector
       implements ReferralConnector
{
  /**
   * Creates a new instance of this test referral connector.
   */
  public TestReferralConnector()
  {
    // No implementation is required.
  }



  /**
   * {@inheritDoc}
   */
  public LDAPConnection getReferralConnection(final LDAPURL referralURL,
                                              final LDAPConnection connection)
         throws LDAPException
  {
    return new LDAPConnection(referralURL.getHost(), referralURL.getPort());
  }
}
