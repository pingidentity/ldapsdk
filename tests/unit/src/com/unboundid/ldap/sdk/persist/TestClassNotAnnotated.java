/*
 * Copyright 2009-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2017 UnboundID Corp.
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
 * This class provides an object that is not marked with the {@code LDAPObject}
 * annotation but has a field that is.
 */
public class TestClassNotAnnotated
{
  @LDAPField private String testField;
  private String testMethodField;



  /**
   * Creates a new instance of this class.
   */
  public TestClassNotAnnotated()
  {
  }



  /**
   * Gets the {@code testMethodField} value.
   *
   * @return  The {@code testMethodField} value.
   */
  @LDAPGetter(attribute="testMethodField")
  public String getTestMethodField()
  {
    return testMethodField;
  }



  /**
   * Sets the {@code testMethodField} value.
   *
   * @param  testMethodField  The {@code testMethodField} value.
   */
  @LDAPSetter(attribute="testMethodField")
  public void setTestMethodField(final String testMethodField)
  {
    this.testMethodField = testMethodField;
  }
}
