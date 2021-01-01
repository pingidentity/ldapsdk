/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of general test cases for the
 * {@code DraftChuLDAPLogSchema00Entry} class and subclasses.
 */
public final class DraftChuLDAPLogSchema00EntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to decode an entry without a start time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoStartTime()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqSession=1234,cn=log",
         "objectClass: auditAbandon",
         "reqType: abandon",
         "reqSession: 1234",
         "reqAuthzID: cn=manager,dc=example,dc=com",
         "reqId: 5678"));
  }



  /**
   * Tests the behavior when trying to decode an entry with a malformed start
   * time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedStartTime()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=malformed,cn=log",
         "objectClass: auditAbandon",
         "reqStart: malformed",
         "reqType: abandon",
         "reqSession: 1234",
         "reqAuthzID: cn=manager,dc=example,dc=com",
         "reqId: 5678"));
  }



  /**
   * Tests the behavior when trying to decode an entry with a malformed end
   * time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedEndTime()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAbandon",
         "reqStart: 20160102030406.789012Z",
         "reqEnd: malformed",
         "reqType: abandon",
         "reqSession: 1234",
         "reqAuthzID: cn=manager,dc=example,dc=com",
         "reqId: 5678"));
  }



  /**
   * Tests the behavior when trying to decode an entry that is missing the
   * session ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingSessionID()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAbandon",
         "reqStart: 20160102030406.789012Z",
         "reqType: abandon",
         "reqAuthzID: cn=manager,dc=example,dc=com",
         "reqId: 5678"));
  }



  /**
   * Tests the behavior when trying to decode an entry that has a malformed set
   * of request controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedRequestControls()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAbandon",
         "reqStart: 20160102030406.789012Z",
         "reqType: abandon",
         "reqSession: 1234",
         "reqAuthzID: cn=manager,dc=example,dc=com",
         "reqId: 5678",
         "reqControls: malformed"));
  }



  /**
   * Tests the behavior when trying to decode an entry that has a malformed set
   * of response controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedResponseControls()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAbandon",
         "reqStart: 20160102030406.789012Z",
         "reqType: abandon",
         "reqSession: 1234",
         "reqAuthzID: cn=manager,dc=example,dc=com",
         "reqId: 5678",
         "reqRespControls: malformed"));
  }



  /**
   * Tests the behavior when trying to decode an entry that has a malformed
   * result code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedResultCode()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAbandon",
         "reqStart: 20160102030406.789012Z",
         "reqType: abandon",
         "reqSession: 1234",
         "reqAuthzID: cn=manager,dc=example,dc=com",
         "reqId: 5678",
         "reqResult: malformed"));
  }



  /**
   * Tests the behavior when trying to decode an entry without a request type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingRequestType()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAbandon",
         "reqStart: 20160102030406.789012Z",
         "reqSession: 1234",
         "reqAuthzID: cn=manager,dc=example,dc=com",
         "reqId: 5678"));
  }



  /**
   * Tests the behavior when trying to decode an entry with an invalid request
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidRequestType()
         throws Exception
  {
    DraftChuLDAPLogSchema00Entry.decode(new Entry(
         "dn: reqStart=20160102030406.789012Z,cn=log",
         "objectClass: auditAbandon",
         "reqStart: 20160102030406.789012Z",
         "reqType: invalid",
         "reqSession: 1234",
         "reqAuthzID: cn=manager,dc=example,dc=com",
         "reqId: 5678"));
  }
}
