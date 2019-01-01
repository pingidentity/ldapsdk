/*
 * Copyright 2016-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2019 Ping Identity Corporation
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
 * This class provides test coverage for the PreEncodedLDIFEntry class.
 */
public final class PreEncodedLDIFEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a pre-encoded entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPreEncodedEntry()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final String ldifString = e.toLDIFString();
    assertNotNull(ldifString);

    final byte[] ldifBytes = ldifString.getBytes("UTF-8");
    assertNotNull(ldifBytes);
    assertTrue(ldifBytes.length > 0);

    final PreEncodedLDIFEntry preEncodedLDIFEntry =
         new PreEncodedLDIFEntry(e, ldifBytes);

    assertNotNull(preEncodedLDIFEntry.getLDIFBytes());
    assertEquals(preEncodedLDIFEntry.getLDIFBytes(), ldifBytes);
  }
}
