/*
 * Copyright 2019-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019-2020 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.transformations;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the exclude all entries
 * transformation.
 */
public final class ExcludeAllEntriesTransformationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the transformation methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTransformation()
         throws Exception
  {
    final ExcludeAllEntriesTransformation t =
         new ExcludeAllEntriesTransformation();

    final Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertNull(t.transformEntry(e));

    assertNull(t.translate(e, 0));

    assertNull(t.translateEntryToWrite(e));
  }
}
