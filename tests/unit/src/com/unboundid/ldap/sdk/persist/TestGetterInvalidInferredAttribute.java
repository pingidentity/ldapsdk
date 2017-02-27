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
 * This class provides an implementation of an object which contains a getter
 * method in which the attribute name should be inferred but the method does
 * not start with "get".
 */
@LDAPObject()
public class TestGetterInvalidInferredAttribute
{
  /**
   * Creates a new instance of this object.
   */
  public TestGetterInvalidInferredAttribute()
  {
    // No implementation required.
  }



  /**
   * Retrieves the string "a break".
   *
   * @return  The string "a break".
   */
  @LDAPGetter(inRDN=true)
  public String gimmieABreak()
  {
    return "a break";
  }
}
