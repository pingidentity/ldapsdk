/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
 * This class provides an object which may be used to test object inheritance
 * with the persistence framework.  It extends the TestInheritanceL1 class, and
 * may itself be extended.
 */
@LDAPObject(structuralClass="testInheritanceL2",
            defaultParentDN="dc=example,dc=com")
public class TestInheritanceL2
       extends TestInheritanceL1
{
  // A DN field.
  @LDAPDNField()
  private String dn;

  // An optional field.
  @LDAPField(attribute="optionalL2",
             filterUsage=FilterUsage.CONDITIONALLY_ALLOWED)
  private String optionalL2;

  // A required field.
  @LDAPField(attribute="requiredL2",
             requiredForEncode=true,
             requiredForDecode=true,
             inRDN=true,
             filterUsage=FilterUsage.ALWAYS_ALLOWED)
  private String requiredL2;



  /**
   * Creates a new instance of this object with no fields set.
   */
  public TestInheritanceL2()
  {
    dn         = null;
    optionalL2 = null;
    requiredL2 = null;
  }



  /**
   * Retrieves the value of the optionalL2 field.
   *
   * @return  The value of the optionalL2 field.
   */
  public String getOptionalL2()
  {
    return optionalL2;
  }



  /**
   * Sets the value of the optionalL2 field.
   *
   * @param  optionalL2  The value for the optionalL2 field.
   */
  public void setOptionalL2(final String optionalL2)
  {
    this.optionalL2 = optionalL2;
  }



  /**
   * Retrieves the value of the requiredL2 field.
   *
   * @return  The value of the requiredL2 field.
   */
  public String getRequiredL2()
  {
    return requiredL2;
  }



  /**
   * Sets the value of the requiredL2 field.
   *
   * @param  requiredL2  The value for the requiredL2 field.
   */
  public void setRequiredL2(final String requiredL2)
  {
    this.requiredL2 = requiredL2;
  }



  /**
   * Retrieves the value of the DN field for this object.
   *
   * @return  The value of the DN field for this object.
   */
  public String getL2DN()
  {
    return dn;
  }



  /**
   * Sets the value of the DN field for this object.
   *
   * @param  dn  The DN to set.
   */
  public void setL2DN(final String dn)
  {
    this.dn = dn;
  }
}
