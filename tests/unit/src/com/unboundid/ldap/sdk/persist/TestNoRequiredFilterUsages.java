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
package com.unboundid.ldap.sdk.persist;



/**
 * This class provides an object containing fields and methods with all types of
 * filter usages except required.
 */
@LDAPObject()
public final class TestNoRequiredFilterUsages
{
  @LDAPField(inRDN=true, filterUsage=FilterUsage.ALWAYS_ALLOWED)
  private String aAF;

  @LDAPField(filterUsage=FilterUsage.CONDITIONALLY_ALLOWED)
  private String cAF;

  @LDAPField(filterUsage=FilterUsage.EXCLUDED)
  private String eF;

  private String aAM;
  private String cAM;
  private String eM;



  /**
   * Creates a new instance of this class.
   */
  public TestNoRequiredFilterUsages()
  {
  }



  /**
   * Retrieves the value of aAF.
   *
   * @return  The value of aAF.
   */
  public String getAAF()
  {
    return aAF;
  }



  /**
   * Sets the value of aAF.
   *
   * @param  aAF  The value of aAF.
   */
  public void setAAF(final String aAF)
  {
    this.aAF = aAF;
  }



  /**
   * Retrieves the value of cAF.
   *
   * @return  The value of cAF.
   */
  public String getCAF()
  {
    return cAF;
  }



  /**
   * Sets the value of cAF.
   *
   * @param  cAF  The value of cAF.
   */
  public void setCAF(final String cAF)
  {
    this.cAF = cAF;
  }



  /**
   * Retrieves the value of eF.
   *
   * @return  The value of eF.
   */
  public String getEF()
  {
    return eF;
  }



  /**
   * Sets the value of eF.
   *
   * @param  eF  The value of eF.
   */
  public void setEF(final String eF)
  {
    this.eF = eF;
  }



  /**
   * Retrieves the value of aAM.
   *
   * @return  The value of aAM.
   */
  @LDAPGetter(attribute="aAM", filterUsage=FilterUsage.ALWAYS_ALLOWED)
  public String getAAM()
  {
    return aAM;
  }



  /**
   * Sets the value of aAM.
   *
   * @param  aAM  The value of aAM.
   */
  @LDAPSetter(attribute="aAM")
  public void setAAM(final String aAM)
  {
    this.aAM = aAM;
  }



  /**
   * Retrieves the value of cAM.
   *
   * @return  The value of cAM.
   */
  @LDAPGetter(attribute="cAM",
       filterUsage=FilterUsage.CONDITIONALLY_ALLOWED)
  public String getCAM()
  {
    return cAM;
  }



  /**
   * Sets the value of cAM.
   *
   * @param  cAM  The value of cAM.
   */
  @LDAPSetter(attribute="cAM")
  public void setCAM(final String cAM)
  {
    this.cAM = cAM;
  }



  /**
   * Retrieves the value of eM.
   *
   * @return  The value of eM.
   */
  @LDAPGetter(attribute="eM", filterUsage=FilterUsage.EXCLUDED)
  public String getEM()
  {
    return eM;
  }



  /**
   * Sets the value of eM.
   *
   * @param  eM  The value of eM.
   */
  @LDAPSetter(attribute="eM")
  public void setEM(final String eM)
  {
    this.eM = eM;
  }
}
