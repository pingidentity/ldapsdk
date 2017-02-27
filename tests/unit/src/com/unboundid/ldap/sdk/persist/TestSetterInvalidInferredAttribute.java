/*
 * Copyright 2010-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2017 UnboundID Corp.
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
 * This class provides an implementation of an object which contains a setter
 * method in which the attribute name should be inferred but the method does
 * not start with "get".
 */
@LDAPObject()
public class TestSetterInvalidInferredAttribute
{
  // The field used in this class.
  private String x;


  /**
   * Creates a new instance of this object.
   */
  public TestSetterInvalidInferredAttribute()
  {
    // No implementation required.
  }



  /**
   * Retrieves the value of x.
   *
   * @return  The value of x.
   */
  @LDAPGetter(inRDN=true)
  public String getX()
  {
    return x;
  }



  /**
   * Sets the value of x.
   *
   * @param  x  The value to use for X.
   */
  @LDAPSetter()
  public void assignX(final String x)
  {
    this.x = x;
  }
}
