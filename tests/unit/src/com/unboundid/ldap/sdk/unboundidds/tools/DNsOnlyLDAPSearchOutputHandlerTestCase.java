/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;




import java.io.ByteArrayOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;



/**
 * Provides test coverage for the values-only output handler.
 */
public final class DNsOnlyLDAPSearchOutputHandlerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Test with a tool that has a byte array output stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testByteArrayOutputStream()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final LDAPSearch ldapSearch = new LDAPSearch(out, null);

    final DNsOnlyLDAPSearchOutputHandler handler =
         new DNsOnlyLDAPSearchOutputHandler(ldapSearch);

    handler.formatHeader();

    handler.formatSearchResultEntry(new SearchResultEntry(new Entry(
         "dn: dc=example,dc=com",
         "dc: example")));

    handler.formatSearchResultReference(null);

    handler.formatResult(null);

    handler.formatUnsolicitedNotification(null, null);

    final ByteStringBuffer expectedOutputBuffer = new ByteStringBuffer();
    expectedOutputBuffer.append("dc=example,dc=com");
    expectedOutputBuffer.append(StaticUtils.EOL_BYTES);

    assertEquals(out.toByteArray(), expectedOutputBuffer.toByteArray());
  }



  /**
   * Test with a tool that has a null output stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullOutputStream()
         throws Exception
  {
    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final DNsOnlyLDAPSearchOutputHandler handler =
         new DNsOnlyLDAPSearchOutputHandler(ldapSearch);

    handler.formatHeader();

    handler.formatSearchResultEntry(new SearchResultEntry(new Entry(
         "dn: dc=example,dc=com",
         "dc: example")));

    handler.formatSearchResultReference(null);

    handler.formatResult(null);

    handler.formatUnsolicitedNotification(null, null);
  }
}
