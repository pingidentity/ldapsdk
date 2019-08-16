/*
 * Copyright 2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the password policy selection
 * type enum for use with the generate password extended request.
 */
public final class GeneratePasswordPolicySelectionTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the enum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnum()
         throws Exception
  {
    for (final GeneratePasswordPolicySelectionType t :
         GeneratePasswordPolicySelectionType.values())
    {
      assertNotNull(t.name());

      assertEquals(GeneratePasswordPolicySelectionType.forType(t.getBERType()),
           t);

      assertEquals(GeneratePasswordPolicySelectionType.valueOf(t.name()),
           t);
    }

    assertNull(GeneratePasswordPolicySelectionType.forType((byte) 0xFF));

    try
    {
      GeneratePasswordPolicySelectionType.valueOf("undefined value");
      fail("Expected an exception when calling valueOf with an undefined " +
           "value.");
    }
    catch (final Exception e)
    {
      // This was expected.
    }
  }
}
