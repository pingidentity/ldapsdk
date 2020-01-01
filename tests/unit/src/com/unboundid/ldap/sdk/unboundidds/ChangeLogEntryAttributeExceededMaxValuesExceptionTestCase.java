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
package com.unboundid.ldap.sdk.unboundidds;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the changelog entry attribute exceeded
 * max values exception.
 */
public final class ChangeLogEntryAttributeExceededMaxValuesExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testException()
         throws Exception
  {
    final ChangeLogEntryAttributeExceededMaxValuesException e =
         new ChangeLogEntryAttributeExceededMaxValuesException("foo",
              new ChangeLogEntryAttributeExceededMaxValuesCount(
                   "attr=description,beforeCount=1,afterCount=2"));

    assertNotNull(e);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "foo");

    assertNotNull(e.getAttributeInfo());
    assertEquals(e.getAttributeInfo().getAttributeName(), "description");
    assertEquals(e.getAttributeInfo().getBeforeCount(), 1);
    assertEquals(e.getAttributeInfo().getAfterCount(), 2);
  }
}
