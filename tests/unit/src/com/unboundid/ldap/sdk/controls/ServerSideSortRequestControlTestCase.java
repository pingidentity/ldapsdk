/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.controls;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the ServerSideSortRequestControl
 * class.
 */
public class ServerSideSortRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a single sort key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1SingleSortKey()
         throws Exception
  {
    ServerSideSortRequestControl c =
         new ServerSideSortRequestControl(new SortKey("ou"));
    c = new ServerSideSortRequestControl(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getSortKeys());
    assertEquals(c.getSortKeys().length, 1);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with a multiple sort keys.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1MultipleSortKeys()
         throws Exception
  {
    ServerSideSortRequestControl c =
         new ServerSideSortRequestControl(new SortKey("sn"),
                                          new SortKey("givenName"),
                                          new SortKey("uid"));
    c = new ServerSideSortRequestControl(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getSortKeys());
    assertEquals(c.getSortKeys().length, 3);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with no sort keys.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoSortKeys()
  {
    new ServerSideSortRequestControl();
  }



  /**
   * Tests the first constructor with a {@code null} sort key.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullSortKey()
  {
    new ServerSideSortRequestControl((SortKey[]) null);
  }



  /**
   * Tests the second constructor with a single sort key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SingleSortKey()
         throws Exception
  {
    ServerSideSortRequestControl c =
         new ServerSideSortRequestControl(true, new SortKey("ou"));
    c = new ServerSideSortRequestControl(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getSortKeys());
    assertEquals(c.getSortKeys().length, 1);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a multiple sort keys.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2MultipleSortKeys()
         throws Exception
  {
    ServerSideSortRequestControl c =
         new ServerSideSortRequestControl(true,
                  new SortKey("sn"), new SortKey("givenName"),
                  new SortKey("uid"));
    c = new ServerSideSortRequestControl(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getSortKeys());
    assertEquals(c.getSortKeys().length, 3);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with no sort keys.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NoSortKeys()
  {
    new ServerSideSortRequestControl(true);
  }



  /**
   * Tests the second constructor with a {@code null} sort key.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullSortKey()
  {
    new ServerSideSortRequestControl(true, (SortKey[]) null);
  }



  /**
   * Tests the third constructor with a generic control with no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NoValue()
         throws Exception
  {
    Control c =
         new Control(ServerSideSortRequestControl.SERVER_SIDE_SORT_REQUEST_OID,
                     true, null);
    new ServerSideSortRequestControl(c);
  }



  /**
   * Tests the third constructor with a generic control with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3InvalidValue()
         throws Exception
  {
    Control c =
         new Control(ServerSideSortRequestControl.SERVER_SIDE_SORT_REQUEST_OID,
                     true, new ASN1OctetString("foo"));
    new ServerSideSortRequestControl(c);
  }



  /**
   * Tests the constructor with a list of sort keys.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListOfSortKeys()
         throws Exception
  {
    ServerSideSortRequestControl c = new ServerSideSortRequestControl(
         Arrays.asList(new SortKey("sn"), new SortKey("givenName")));

    c = new ServerSideSortRequestControl(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getSortKeys());
    assertEquals(c.getSortKeys().length, 2);

    assertEquals(c.getSortKeys()[0].getAttributeName(), "sn");
    assertEquals(c.getSortKeys()[1].getAttributeName(), "givenName");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Creates a number of entries in the server and retrieves them sorted in both
   * forward and reversed order.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithSortControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    for (int i=0; i < 10; i++)
    {
      String dn = "ou=" + i + "," + getTestBaseDN();
      Attribute[] attrs =
      {
        new Attribute("objectClass", "top", "organizationalUnit"),
        new Attribute("ou", String.valueOf(i))
      };

      conn.add(dn, attrs);
    }


    Control[] controls =
    {
      new ServerSideSortRequestControl(true, new SortKey("ou", false))
    };

    SearchRequest searchRequest =
         new SearchRequest(getTestBaseDN(), SearchScope.ONE,
                           "(objectClass=*)");
    searchRequest.setControls(controls);

    SearchResult searchResult1 = conn.search(searchRequest);
    List<SearchResultEntry> entryList1 = searchResult1.getSearchEntries();

    boolean sortResultFound = false;
    for (Control c : searchResult1.getResponseControls())
    {
      if (c instanceof ServerSideSortResponseControl)
      {
        sortResultFound = true;
        ServerSideSortResponseControl sssrc = (ServerSideSortResponseControl) c;
        assertEquals(sssrc.getResultCode(), ResultCode.SUCCESS);
        assertNull(sssrc.getAttributeName());
        assertNotNull(sssrc.toString());
      }
      else if (c.getOID().equals(ServerSideSortResponseControl.
                                      SERVER_SIDE_SORT_RESPONSE_OID))
      {
        fail("Did not properly decode the first server-side sort response " +
             "control");
      }
    }
    assertTrue(sortResultFound);


    controls = new Control[]
    {
      new ServerSideSortRequestControl(true, new SortKey("ou", true))
    };

    searchRequest = new SearchRequest(getTestBaseDN(), SearchScope.ONE,
                                      "(objectClass=*)");
    searchRequest.setControls(controls);

    SearchResult searchResult2 = conn.search(searchRequest);
    List<SearchResultEntry> entryList2 = searchResult2.getSearchEntries();

    sortResultFound = false;
    for (Control c : searchResult2.getResponseControls())
    {
      if (c instanceof ServerSideSortResponseControl)
      {
        sortResultFound = true;
        ServerSideSortResponseControl sssrc = (ServerSideSortResponseControl) c;
        assertEquals(sssrc.getResultCode(), ResultCode.SUCCESS);
        assertNull(sssrc.getAttributeName());
        assertNotNull(sssrc.toString());
      }
      else if (c.getOID().equals(ServerSideSortResponseControl.
                                      SERVER_SIDE_SORT_RESPONSE_OID))
      {
        fail("Did not properly decode the second server-side sort response " +
             "control");
      }
    }
    assertTrue(sortResultFound);


    assertFalse(entryList1.equals(entryList2));

    ArrayList<SearchResultEntry> reversedList2 =
         new ArrayList<SearchResultEntry>(entryList2.size());
    for (SearchResultEntry e : entryList2)
    {
      reversedList2.add(0, e);
    }

    assertEquals(entryList1, reversedList2);



    controls = new Control[]
    {
      new SubtreeDeleteRequestControl()
    };

    conn.delete(new DeleteRequest(getTestBaseDN(), controls));
    conn.close();
  }
}
