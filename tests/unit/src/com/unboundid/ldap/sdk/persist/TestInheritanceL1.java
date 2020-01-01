/*
 * Copyright 2011-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2020 Ping Identity Corporation
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



import com.unboundid.ldap.sdk.ReadOnlyEntry;



/**
 * This class provides an object which may be used to test object inheritance
 * with the persistence framework.  This object does not have any superclass,
 * but is expected to be extended.
 */
@LDAPObject(structuralClass="testInheritanceL1",
            defaultParentDN="dc=example,dc=com")
public class TestInheritanceL1
{
  // An entry field.
  @LDAPEntryField()
  private ReadOnlyEntry entry;

  // An optional field.
  @LDAPField(attribute="optionalL1",
             filterUsage=FilterUsage.CONDITIONALLY_ALLOWED)
  private String optionalL1;

  // A required field.
  @LDAPField(attribute="requiredL1",
             requiredForEncode=true,
             requiredForDecode=true,
             inRDN=true,
             filterUsage=FilterUsage.ALWAYS_ALLOWED)
  private String requiredL1;



  /**
   * Creates a new instance of this object with no fields set.
   */
  public TestInheritanceL1()
  {
    entry      = null;
    optionalL1 = null;
    requiredL1 = null;
  }



  /**
   * Retrieves the value of the optionalL1 field.
   *
   * @return  The value of the optionalL1 field.
   */
  public String getOptionalL1()
  {
    return optionalL1;
  }



  /**
   * Sets the value of the optionalL1 field.
   *
   * @param  optionalL1  The value for the optionalL1 field.
   */
  public void setOptionalL1(final String optionalL1)
  {
    this.optionalL1 = optionalL1;
  }



  /**
   * Retrieves the value of the requiredL1 field.
   *
   * @return  The value of the requiredL1 field.
   */
  public String getRequiredL1()
  {
    return requiredL1;
  }



  /**
   * Sets the value of the requiredL1 field.
   *
   * @param  requiredL1  The value for the requiredL1 field.
   */
  public void setRequiredL1(final String requiredL1)
  {
    this.requiredL1 = requiredL1;
  }



  /**
   * Retrieves the value of the entry field for this object.
   *
   * @return  The value of the entry field for this object.
   */
  public ReadOnlyEntry getL1Entry()
  {
    return entry;
  }



  /**
   * Sets the value of the entry field for this object.
   *
   * @param  e  The entry to set.
   */
  public void setL1Entry(final ReadOnlyEntry e)
  {
    entry = e;
  }
}
