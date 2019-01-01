/*
 * Copyright 2009-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2019 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.persist;



/**
 * This class provides an object with the {@code LDAPObject} annotation that
 * does not have a zero-argument constructor.
 */
@LDAPObject()
public class TestNoDefaultConstructor
{
  @LDAPField(attribute="a", inRDN=true, filterUsage=FilterUsage.ALWAYS_ALLOWED)
  private String a;



  /**
   * Creates a new instance of this object.
   *
   * @param  arg  The argument for this constructor.
   */
  public TestNoDefaultConstructor(final String arg)
  {
  }
}
