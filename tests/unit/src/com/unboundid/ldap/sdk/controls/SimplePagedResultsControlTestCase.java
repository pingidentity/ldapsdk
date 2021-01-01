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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class provides a set of test cases for the SimplePagedResultsControl
 * class.
 */
public class SimplePagedResultsControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    SimplePagedResultsControl c = new SimplePagedResultsControl();
  }



  /**
   * Tests the second constructor.
   */
  @Test()
  public void testConstructor2()
  {
    SimplePagedResultsControl c = new SimplePagedResultsControl(3);

    assertEquals(c.getSize(), 3);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().getValue().length, 0);
    assertFalse(c.moreResultsToReturn());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor.
   */
  @Test()
  public void testConstructor3()
  {
    SimplePagedResultsControl c = new SimplePagedResultsControl(3, true);

    assertEquals(c.getSize(), 3);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().getValue().length, 0);
    assertFalse(c.moreResultsToReturn());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with a non-{@code null} cookie.
   */
  @Test()
  public void testConstructor4()
  {
    SimplePagedResultsControl c =
         new SimplePagedResultsControl(3, new ASN1OctetString());

    assertEquals(c.getSize(), 3);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().getValue().length, 0);
    assertFalse(c.moreResultsToReturn());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with a {@code null} cookie.
   */
  @Test()
  public void testConstructor4NullCookie()
  {
    SimplePagedResultsControl c = new SimplePagedResultsControl(3, null);

    assertEquals(c.getSize(), 3);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().getValue().length, 0);
    assertFalse(c.moreResultsToReturn());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor with a non-{@code null} cookie.
   */
  @Test()
  public void testConstructor5()
  {
    SimplePagedResultsControl c =
         new SimplePagedResultsControl(3, new ASN1OctetString(new byte[5]),
                                       true);

    assertEquals(c.getSize(), 3);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().getValue().length, 5);
    assertTrue(c.moreResultsToReturn());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor with a {@code null} cookie.
   */
  @Test()
  public void testConstructor5NullCookie()
  {
    SimplePagedResultsControl c = new SimplePagedResultsControl(3, null, true);

    assertEquals(c.getSize(), 3);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().getValue().length, 0);
    assertFalse(c.moreResultsToReturn());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the sixth constructor with a valid size and non-empty cookie.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6NonEmptyCookie()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Integer(10),
      new ASN1OctetString(new byte[5])
    };

    SimplePagedResultsControl c =
       new SimplePagedResultsControl("1.2.840.113556.1.4.319", false,
                new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertEquals(c.getSize(), 10);

    assertNotNull(c.getCookie());
    assertTrue(c.moreResultsToReturn());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the sixth constructor with a valid size and an empty cookie.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6EmptyCookie()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Integer(10),
      new ASN1OctetString()
    };

    SimplePagedResultsControl c =
       new SimplePagedResultsControl("1.2.840.113556.1.4.319", false,
                new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertEquals(c.getSize(), 10);

    assertNotNull(c.getCookie());
    assertFalse(c.moreResultsToReturn());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the sixth constructor with a {@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor6NullValue()
         throws Exception
  {
    new SimplePagedResultsControl("1.2.840.113556.1.4.319", false, null);
  }



  /**
   * Tests the sixth constructor with a {@code null} value that is not a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor6ValueNotSequence()
         throws Exception
  {
    new SimplePagedResultsControl("1.2.840.113556.1.4.319", false,
             new ASN1OctetString(new ASN1Integer(5).encode()));
  }



  /**
   * Tests the sixth constructor with a {@code null} value sequence wtih an
   * invalid element count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor6ValueSequenceInvalidElementCount()
         throws Exception
  {
    new SimplePagedResultsControl("1.2.840.113556.1.4.319", false,
             new ASN1OctetString(new ASN1Sequence().encode()));
  }



  /**
   * Tests the sixth constructor with a {@code null} value sequence in which the
   * first element cannot be decoded as an integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor6ValueSequenceFirstElementNotInteger()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString(),
      new ASN1OctetString()
    };

    new SimplePagedResultsControl("1.2.840.113556.1.4.319", false,
             new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Add multiple entries to the server and then iterate through them three at a
   * time using the simple paged results control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithPagedResultsControl()
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


    int iterationCount = 0;
    SearchResult searchResult = null;
    SimplePagedResultsControl responseControl = null;
    do
    {
      iterationCount++;

      Control[] controls;
      if (responseControl == null)
      {
        controls = new Control[]
        {
          new SimplePagedResultsControl(3, true)
        };
      }
      else
      {
        controls = new Control[]
        {
          new SimplePagedResultsControl(3, responseControl.getCookie(), true)
        };
      }

      SearchRequest searchRequest =
           new SearchRequest(getTestBaseDN(), SearchScope.ONE,
                             "(objectClass=*)");
      searchRequest.setControls(controls);
      searchResult = conn.search(searchRequest);

      responseControl = null;
      for (Control c : searchResult.getResponseControls())
      {
        if (c instanceof SimplePagedResultsControl)
        {
          responseControl = (SimplePagedResultsControl) c;
          assertNotNull(responseControl.toString());
        }
      }

      assertNotNull(responseControl);
    } while (responseControl.moreResultsToReturn());

    assertTrue(iterationCount > 1);


    Control[] controls =
    {
      new SubtreeDeleteRequestControl()
    };

    conn.delete(new DeleteRequest(getTestBaseDN(), controls));
    conn.close();
  }



  /**
   * Tests the {@code get} method with a result that does not contain a simple
   * paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    final SimplePagedResultsControl c = SimplePagedResultsControl.get(r);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new SimplePagedResultsControl(10, new ASN1OctetString("foo"), false)
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    final SimplePagedResultsControl c = SimplePagedResultsControl.get(r);
    assertNotNull(c);

    assertEquals(c.getSize(), 10);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().stringValue(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a simple paged results
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new SimplePagedResultsControl(10,
         new ASN1OctetString("foo"), false);

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    final SimplePagedResultsControl c = SimplePagedResultsControl.get(r);
    assertNotNull(c);

    assertEquals(c.getSize(), 10);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().stringValue(), "foo");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a simple paged results
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(SimplePagedResultsControl.PAGED_RESULTS_OID, false, null)
    };

    final SearchResult r = new SearchResult(1, ResultCode.SUCCESS, null, null,
         null, 10, 0, controls);

    SimplePagedResultsControl.get(r);
  }
}
