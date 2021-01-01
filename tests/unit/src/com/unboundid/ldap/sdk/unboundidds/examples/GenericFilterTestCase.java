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
package com.unboundid.ldap.sdk.unboundidds.examples;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code GenericFilter} class.
 */
public class GenericFilterTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for search filters.
   *
   * @param  f  The string representation of the filter to test.
   * @param  g  The expected string representation for the generic filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testFilters")
  public void testGenericFilters(String f, String g)
         throws Exception
  {
    GenericFilter gf = new GenericFilter(Filter.create(f));

    assertNotNull(gf);
    assertEquals(gf.toString(), g);

    gf.hashCode();

    assertFalse(gf.equals(null));
    assertTrue(gf.equals(gf));
    assertFalse(gf.equals(f));
    assertTrue(gf.equals(new GenericFilter(Filter.create(f))));
    assertFalse(gf.equals(new GenericFilter(
         Filter.create("(&" + f + "(c=d))"))));


    f = "(!" + f + ')';
    g = "(!" + g + ')';
    gf = new GenericFilter(Filter.create(f));

    assertNotNull(gf);
    assertEquals(gf.toString(), g);

    gf.hashCode();

    assertFalse(gf.equals(null));
    assertTrue(gf.equals(gf));
    assertFalse(gf.equals(f));
    assertTrue(gf.equals(new GenericFilter(Filter.create(f))));
    assertFalse(gf.equals(new GenericFilter(
         Filter.create("(&" + f + "(c=d))"))));
  }



  /**
   * Provides test data for this class.
   *
   * @return  Test data for this class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "testFilters")
  public Object[][] getTestFilters()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        "(a=)",
        "(a=?)",
      },

      new Object[]
      {
        "(a=b)",
        "(a=?)",
      },

      new Object[]
      {
        "(A=b)",
        "(a=?)",
      },

      new Object[]
      {
        "(a>=)",
        "(a>=?)",
      },

      new Object[]
      {
        "(a>=b)",
        "(a>=?)",
      },

      new Object[]
      {
        "(A>=b)",
        "(a>=?)",
      },

      new Object[]
      {
        "(a<=)",
        "(a<=?)",
      },

      new Object[]
      {
        "(a<=b)",
        "(a<=?)",
      },

      new Object[]
      {
        "(A<=b)",
        "(a<=?)",
      },

      new Object[]
      {
        "(a=*)",
        "(a=*)",
      },

      new Object[]
      {
        "(a~=)",
        "(a~=?)",
      },

      new Object[]
      {
        "(a~=b)",
        "(a~=?)",
      },

      new Object[]
      {
        "(A~=b)",
        "(a~=?)",
      },

      new Object[]
      {
        "(&)",
        "(&)",
      },

      new Object[]
      {
        "(&(a=foo))",
        "(&(a=?))",
      },

      new Object[]
      {
        "(&(a=b)(c=d))",
        "(&(a=?)(c=?))",
      },

      new Object[]
      {
        "(&(c=)(a=))",
        "(&(a=?)(c=?))",
      },

      new Object[]
      {
        "(|)",
        "(|)",
      },

      new Object[]
      {
        "(|(a=foo))",
        "(|(a=?))",
      },

      new Object[]
      {
        "(|(a=b)(c=d))",
        "(|(a=?)(c=?))",
      },

      new Object[]
      {
        "(|(c=)(a=))",
        "(|(a=?)(c=?))",
      },

      new Object[]
      {
        "(a=b*)",
        "(a=?*)",
      },

      new Object[]
      {
        "(a=*b*)",
        "(a=*?*)",
      },

      new Object[]
      {
        "(a=*b)",
        "(a=*?)",
      },

      new Object[]
      {
        "(a=b*c*d)",
        "(a=?*?*?)",
      },

      new Object[]
      {
        "(a=b*c*d*e*f)",
        "(a=?*?*?*?*?)",
      },

      new Object[]
      {
        "(a:=b)",
        "(a:=?)",
      },

      new Object[]
      {
        "(a:dn:=b)",
        "(a:dn:=?)",
      },

      new Object[]
      {
        "(:1.2.3.4:=b)",
        "(:1.2.3.4:=?)",
      },


      new Object[]
      {
        "(a:1.2.3.4:=b)",
        "(a:1.2.3.4:=?)",
      },

      new Object[]
      {
        "(a:dn:1.2.3.4:=b)",
        "(a:dn:1.2.3.4:=?)",
      },
    };
  }
}
