/*
 * Copyright 2007-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2017 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.schema;



import java.util.TreeSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the AttributeUsage enum.
 */
public class AttributeUsageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code userApplications} element.
   */
  @Test()
  public void testUserApplications()
  {
    assertEquals(AttributeUsage.USER_APPLICATIONS.getName(),
                 "userApplications");

    assertEquals(AttributeUsage.USER_APPLICATIONS.toString(),
                 "userApplications");

    assertFalse(AttributeUsage.USER_APPLICATIONS.isOperational());

    assertEquals(AttributeUsage.valueOf("USER_APPLICATIONS"),
                 AttributeUsage.USER_APPLICATIONS);

    assertEquals(AttributeUsage.forName("userApplications"),
         AttributeUsage.USER_APPLICATIONS);
  }



  /**
   * Tests the {@code directoryOperation} element.
   */
  @Test()
  public void testDirectoryOperation()
  {
    assertEquals(AttributeUsage.DIRECTORY_OPERATION.getName(),
                 "directoryOperation");

    assertEquals(AttributeUsage.DIRECTORY_OPERATION.toString(),
                 "directoryOperation");

    assertTrue(AttributeUsage.DIRECTORY_OPERATION.isOperational());

    assertEquals(AttributeUsage.valueOf("DIRECTORY_OPERATION"),
                 AttributeUsage.DIRECTORY_OPERATION);

    assertEquals(AttributeUsage.forName("directoryOperation"),
         AttributeUsage.DIRECTORY_OPERATION);
  }



  /**
   * Tests the {@code distributedOperation} element.
   */
  @Test()
  public void testDistributedOperation()
  {
    assertEquals(AttributeUsage.DISTRIBUTED_OPERATION.getName(),
                 "distributedOperation");

    assertEquals(AttributeUsage.DISTRIBUTED_OPERATION.toString(),
                 "distributedOperation");

    assertTrue(AttributeUsage.DISTRIBUTED_OPERATION.isOperational());

    assertEquals(AttributeUsage.valueOf("DISTRIBUTED_OPERATION"),
                 AttributeUsage.DISTRIBUTED_OPERATION);

    assertEquals(AttributeUsage.forName("distributedOperation"),
         AttributeUsage.DISTRIBUTED_OPERATION);
  }



  /**
   * Tests the {@code dSAOperation} element.
   */
  @Test()
  public void testDSAOperation()
  {
    assertEquals(AttributeUsage.DSA_OPERATION.getName(),
                 "dSAOperation");

    assertEquals(AttributeUsage.DSA_OPERATION.toString(),
                 "dSAOperation");

    assertTrue(AttributeUsage.DSA_OPERATION.isOperational());

    assertEquals(AttributeUsage.valueOf("DSA_OPERATION"),
                 AttributeUsage.DSA_OPERATION);

    assertEquals(AttributeUsage.forName("dSAOperation"),
         AttributeUsage.DSA_OPERATION);
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    TreeSet<AttributeUsage> expectedSet = new TreeSet<AttributeUsage>();
    expectedSet.add(AttributeUsage.USER_APPLICATIONS);
    expectedSet.add(AttributeUsage.DIRECTORY_OPERATION);
    expectedSet.add(AttributeUsage.DISTRIBUTED_OPERATION);
    expectedSet.add(AttributeUsage.DSA_OPERATION);

    TreeSet<AttributeUsage> valuesSet = new TreeSet<AttributeUsage>();
    for (AttributeUsage usage : AttributeUsage.values())
    {
      valuesSet.add(usage);
    }

    assertEquals(valuesSet, expectedSet);
  }



  /**
   * Tests the behavior of the {@code forName} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForName()
         throws Exception
  {
    for (final AttributeUsage usage : AttributeUsage.values())
    {
      assertEquals(AttributeUsage.forName(usage.getName()), usage);
      assertEquals(AttributeUsage.forName(usage.getName().toLowerCase()),
           usage);
      assertEquals(AttributeUsage.forName(usage.getName().toUpperCase()),
           usage);
    }

    assertNull(AttributeUsage.forName("undefined"));
  }
}
