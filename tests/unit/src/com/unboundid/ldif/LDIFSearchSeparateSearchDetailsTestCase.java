/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldif;



import java.io.File;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a set of test cases for the
 * {@code LDIFSearchSeparateSearchDetails} class.
 */
public final class LDIFSearchSeparateSearchDetailsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the methods of the LDIFSearchSeparateSearchDetails object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDetailsObject()
         throws Exception
  {
    final LDAPURL url = new LDAPURL(
         "ldap://ds.example.com:389/dc=example,dc=com??sub?(uid=jdoe)");
    final File outputFile = createTempFile();
    final LDIFWriter ldifWriter = new LDIFWriter(outputFile);

    final LDIFSearchSeparateSearchDetails d =
         new LDIFSearchSeparateSearchDetails(url, outputFile, ldifWriter,
              Schema.getDefaultStandardSchema());

    assertNotNull(d.getLDAPURL());
    assertEquals(d.getLDAPURL(), url);

    assertNotNull(d.getOutputFile());
    assertEquals(d.getOutputFile(), outputFile);

    assertNotNull(d.getLDIFWriter());

    assertNotNull(d.getSearchEntryParer());

    ldifWriter.close();
  }
}
