/*
 * Copyright 2014-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2020 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;



/**
 * This class provides a set of test cases for the result code info object.
 */
public final class ResultCodeInfoTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests with a null operation type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullOperationType()
         throws Exception
  {
    final ResultCodeInfo rcInfo = new ResultCodeInfo(0, "Success", null, 123L,
         98.765d,  432.10d, 123.45d);

    assertEquals(rcInfo.intValue(), 0);

    assertNotNull(rcInfo.getName());
    assertEquals(rcInfo.getName(), "Success");

    assertNull(rcInfo.getOperationType());

    assertEquals(rcInfo.getCount(), 123L);

    assertEquals(rcInfo.getPercent(), 98.765d);

    assertEquals(rcInfo.getTotalResponseTimeMillis(), 432.10d);

    assertEquals(rcInfo.getAverageResponseTimeMillis(), 123.45d);
  }



  /**
   * Tests with a non-null operation type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonNullOperationType()
         throws Exception
  {
    final ResultCodeInfo rcInfo = new ResultCodeInfo(80, "Other",
         OperationType.ADD, 987L, 12.34d, 56.78d, 90.12d);

    assertEquals(rcInfo.intValue(), 80);

    assertNotNull(rcInfo.getName());
    assertEquals(rcInfo.getName(), "Other");

    assertNotNull(rcInfo.getOperationType());
    assertEquals(rcInfo.getOperationType(), OperationType.ADD);

    assertEquals(rcInfo.getCount(), 987L);

    assertEquals(rcInfo.getPercent(), 12.34d);

    assertEquals(rcInfo.getTotalResponseTimeMillis(), 56.78d);

    assertEquals(rcInfo.getAverageResponseTimeMillis(), 90.12d);
  }
}
