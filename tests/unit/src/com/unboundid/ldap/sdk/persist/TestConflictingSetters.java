/*
 * Copyright 2009-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2017 Ping Identity Corporation
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
 * This class provides an object with the {@code LDAPObject} annotation that has
 * multiple setter methods targeting the same attribute.
 */
@LDAPObject()
public class TestConflictingSetters
{
  /**
   * Sets the value of x1.
   *
   * @param  x  The value of x1.
   */
  @LDAPGetter(attribute="x")
  public void setX1(final String x)
  {
  }



  /**
   * Sets the value of x2.
   *
   * @param  x  The value of x2.
   */
  @LDAPGetter(attribute="x")
  public void setX2(final String x)
  {
  }
}
