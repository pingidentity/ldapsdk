/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the ChangeType class.
 */
public class ChangeTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code getName} method.
   */
  @Test()
  public void testGetName()
  {
    assertEquals(ChangeType.ADD.getName(), "add");
    assertEquals(ChangeType.DELETE.getName(), "delete");
    assertEquals(ChangeType.MODIFY.getName(), "modify");
    assertEquals(ChangeType.MODIFY_DN.getName(), "moddn");
  }



  /**
   * Tests the {@code forName} method.
   */
  @Test()
  public void testForName()
  {
    assertEquals(ChangeType.forName("add"), ChangeType.ADD);
    assertEquals(ChangeType.forName("delete"), ChangeType.DELETE);
    assertEquals(ChangeType.forName("modify"), ChangeType.MODIFY);
    assertEquals(ChangeType.forName("moddn"), ChangeType.MODIFY_DN);
    assertEquals(ChangeType.forName("modrdn"), ChangeType.MODIFY_DN);

    assertEquals(ChangeType.forName("ADD"), ChangeType.ADD);
    assertEquals(ChangeType.forName("DELETE"), ChangeType.DELETE);
    assertEquals(ChangeType.forName("MODIFY"), ChangeType.MODIFY);
    assertEquals(ChangeType.forName("MODDN"), ChangeType.MODIFY_DN);
    assertEquals(ChangeType.forName("MODRDN"), ChangeType.MODIFY_DN);

    assertEquals(ChangeType.forName("aDd"), ChangeType.ADD);
    assertEquals(ChangeType.forName("dElEtE"), ChangeType.DELETE);
    assertEquals(ChangeType.forName("mOdIfY"), ChangeType.MODIFY);
    assertEquals(ChangeType.forName("mOdDn"), ChangeType.MODIFY_DN);
    assertEquals(ChangeType.forName("mOdRdN"), ChangeType.MODIFY_DN);

    assertNull(ChangeType.forName("invalid"));
  }



  /**
   * Tests the {@code valueOf} method.
   */
  @Test()
  public void testValueOf()
  {
    assertEquals(ChangeType.valueOf("ADD"), ChangeType.ADD);
    assertEquals(ChangeType.valueOf("DELETE"), ChangeType.DELETE);
    assertEquals(ChangeType.valueOf("MODIFY"), ChangeType.MODIFY);
    assertEquals(ChangeType.valueOf("MODIFY_DN"), ChangeType.MODIFY_DN);
  }



  /**
   * Tests the {@code toString} method.
   */
  @Test()
  public void testToString()
  {
    assertEquals(ChangeType.ADD.toString(), "add");
    assertEquals(ChangeType.DELETE.toString(), "delete");
    assertEquals(ChangeType.MODIFY.toString(), "modify");
    assertEquals(ChangeType.MODIFY_DN.toString(), "moddn");
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    assertEquals(ChangeType.values().length, 4);
  }
}
