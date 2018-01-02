/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
 * This class provides a minimal object with multiple fields and getters for
 * inclusion in the entry RDN.
 */
@LDAPObject()
public class TestMinimalObjectMultipleRDNs
{
  /**
   * The value for a.
   */
  @LDAPField(inRDN=true) String a;



  /**
   * The value for b.
   */
  @LDAPField(inRDN=true) String b;



  /**
   * The value for c.
   */
  String c;



  /**
   * The value for d.
   */
  String d;



  /**
   * The DN field.
   */
  @LDAPDNField String dn;



  /**
   * Gets the value of c.
   *
   * @return  The value of c.
   */
  @LDAPGetter(attribute="c", inRDN=true)
  public String getC()
  {
    return c;
  }



  /**
   * Sets the value of c.
   *
   * @param  c  The value of c.
   */
  @LDAPSetter(attribute="c")
  public void setC(final String c)
  {
    this.c = c;
  }



  /**
   * Gets the value of d.
   *
   * @return  The value of d.
   */
  @LDAPGetter(attribute="d", inRDN=true)
  public String getD()
  {
    return d;
  }



  /**
   * Sets the value of d.
   *
   * @param  d  The value of d.
   */
  @LDAPSetter(attribute="d")
  public void setD(final String d)
  {
    this.d = d;
  }
}
