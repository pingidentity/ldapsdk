/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



/**
 * This class provides an implementation of the LDAPBind interface that can be
 * used for testing.
 */
public class TestLDAPBind
       implements LDAPBind
{
  // The DN to use when binding.
  private final String dn;

  // The password to use when binding.
  private final String password;



  /**
   * Creates a new instance of this class with the provided information.
   *
   * @param  dn        The DN to use when binding.
   * @param  password  The password to use when binding.
   */
  public TestLDAPBind(final String dn, final String password)
  {
    this.dn       = dn;
    this.password = password;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void bind(final LDAPConnection conn)
         throws LDAPException
  {
    conn.bind(dn, password);
  }
}
