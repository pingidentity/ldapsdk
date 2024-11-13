/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the {@code MoveSubtreeProperties}
 * class.
 */
public final class MoveSubtreePropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests to ensure that the properties have the expected set of defaults.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaults()
         throws Exception
  {
    MoveSubtreeProperties properties =
         new MoveSubtreeProperties("ou=test,dc=example,dc=com");

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());
  }



  /**
   * Tests methods related to getting and setting the base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBaseDN()
         throws Exception
  {
    MoveSubtreeProperties properties =
         new MoveSubtreeProperties("ou=test,dc=example,dc=com");

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setBaseDN("ou=test2,dc=example,dc=com");
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test2,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    try
    {
      properties.setBaseDN("malformed-dn");
      fail("Expected an exception when trying to set a malformed base DN");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }

    assertEquals(properties.getBaseDN(),
         new DN("ou=test2,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    try
    {
      properties.setBaseDN("");
      fail("Expected an exception when trying to set an empty base DN");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }

    assertEquals(properties.getBaseDN(),
         new DN("ou=test2,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());
  }



  /**
   * Tests methods related to suppressing referential integrity updates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuppressReferentialIntegrityUpdates()
         throws Exception
  {
    MoveSubtreeProperties properties =
         new MoveSubtreeProperties("ou=test,dc=example,dc=com");

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setSuppressReferentialIntegrityUpdates(true);
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertTrue(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setSuppressReferentialIntegrityUpdates(false);
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());
  }



  /**
   * Tests methods related to using the to-be-deleted accessibility state.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseToBeDeletedAccessibilityState()
         throws Exception
  {
    MoveSubtreeProperties properties =
         new MoveSubtreeProperties("ou=test,dc=example,dc=com");

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setUseToBeDeletedAccessibilityState(true);
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertTrue(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setUseToBeDeletedAccessibilityState(false);
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());
  }



  /**
   * Tests methods related to the maximum allowable subtree size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaximumAllowableSubtreeSize()
         throws Exception
  {
    MoveSubtreeProperties properties =
         new MoveSubtreeProperties("ou=test,dc=example,dc=com");

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setMaximumAllowedSubtreeSize(12345);
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 12345);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setMaximumAllowedSubtreeSize(-1);
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setMaximumAllowedSubtreeSize(54321);
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 54321);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setMaximumAllowedSubtreeSize(0);
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());
  }



  /**
   * Tests methods related to the move-subtree listener.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMoveSubtreeListener()
         throws Exception
  {
    MoveSubtreeProperties properties =
         new MoveSubtreeProperties("ou=test,dc=example,dc=com");

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setMoveSubtreeListener(new TestMoveSubtreeListener());
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNotNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setMoveSubtreeListener(null);
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());
  }



  /**
   * Tests methods related to the operation purpose request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOperationPurposeRequestControl()
         throws Exception
  {
    MoveSubtreeProperties properties =
         new MoveSubtreeProperties("ou=test,dc=example,dc=com");

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setOperationPurposeRequestControl(
         new OperationPurposeRequestControl("test-application", "1.2.3.4", 10,
              "Test Purpose"));
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNotNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());


    properties.setOperationPurposeRequestControl(null);
    properties = new MoveSubtreeProperties(properties);

    assertEquals(properties.getBaseDN(),
         new DN("ou=test,dc=example,dc=com"));
    assertFalse(properties.suppressReferentialIntegrityUpdates());
    assertFalse(properties.useToBeDeletedAccessibilityState());
    assertEquals(properties.getMaximumAllowedSubtreeSize(), 0);
    assertNull(properties.getMoveSubtreeListener());
    assertNull(properties.getOperationPurposeRequestControl());
    assertNotNull(properties.toString());
  }
}
