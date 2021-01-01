/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;



/**
 * This class is primarily intended to ensure that code provided in javadoc
 * examples is valid.
 */
public final class ExampleUsagesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the example in the {@code ActiveDirectoryDirSyncControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled = false)
  public void testActiveDirectoryDirSyncControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    // NOTE:  The in-memory directory server doesn't support this control, so
    // this test won't actually be run.  This test just makes sure that the
    // example code compiles.
    LDAPConnection connection = null;
    boolean keepLooping = true;


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create a search request that will be used to identify all users below
    // "dc=example,dc=com".
    final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("objectClass", "User"));

    // Define the components that will be included in the DirSync request
    // control.
    ASN1OctetString cookie = null;
    final int flags = ActiveDirectoryDirSyncControl.FLAG_INCREMENTAL_VALUES |
         ActiveDirectoryDirSyncControl.FLAG_OBJECT_SECURITY;

    // Create a loop that will be used to keep polling for changes.
    while (keepLooping)
    {
      // Update the controls that will be used for the search request.
      searchRequest.setControls(new ActiveDirectoryDirSyncControl(true, flags,
           50, cookie));

      // Process the search and get the response control.
      final SearchResult searchResult = connection.search(searchRequest);
      ActiveDirectoryDirSyncControl dirSyncResponse =
           ActiveDirectoryDirSyncControl.get(searchResult);
      cookie = dirSyncResponse.getCookie();

      // Process the search result entries because they represent entries that
      // have been created or modified.
      for (final SearchResultEntry updatedEntry :
           searchResult.getSearchEntries())
      {
        // Do something with the entry.
      }

      // If the client might want to continue the search even after shutting
      // down and starting back up later, then persist the cookie now.
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the
   * {@code DraftBeheraLDAPPasswordPolicy10RequestControl} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled = false)
  public void testDraftBeheraLDAPPasswordPolicy10RequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    // NOTE:  The in-memory directory server doesn't support this control, so
    // this test won't actually be run.  This test just makes sure that the
    // example code compiles.
    LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    SimpleBindRequest bindRequest = new SimpleBindRequest(
         "uid=john.doe,ou=People,dc=example,dc=com", "password",
         new DraftBeheraLDAPPasswordPolicy10RequestControl());

    BindResult bindResult;
    try
    {
      bindResult = connection.bind(bindRequest);
    }
    catch (LDAPException le)
    {
      // The bind failed.  There may be a password policy response control to
      // help tell us why.
      bindResult = new BindResult(le);
    }

    DraftBeheraLDAPPasswordPolicy10ResponseControl pwpResponse =
         DraftBeheraLDAPPasswordPolicy10ResponseControl.get(bindResult);
    if (pwpResponse != null)
    {
      DraftBeheraLDAPPasswordPolicy10ErrorType errorType =
           pwpResponse.getErrorType();
      if (errorType != null)
      {
        // There was a password policy error.
      }

      DraftBeheraLDAPPasswordPolicy10WarningType warningType =
           pwpResponse.getWarningType();
      if (warningType != null)
      {
        // There was a password policy warning.
        int value = pwpResponse.getWarningValue();
        switch (warningType)
        {
          case TIME_BEFORE_EXPIRATION:
            // The warning value is the number of seconds until expiration.
            break;
          case GRACE_LOGINS_REMAINING:
            // The warning value is the number of grace logins remaining.
        }
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code DraftZeilengaLDAPNoOp12RequestControl}
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled = false)
  public void testDraftZeilengaLDAPNoOp12RequestControlExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    // NOTE:  The in-memory directory server doesn't support this control, so
    // this test won't actually be run.  This test just makes sure that the
    // example code compiles.
    LDAPConnection connection = null;


    /* ----- BEGIN EXAMPLE CODE ----- */
    ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description",
              "new value"));
    modifyRequest.addControl(new DraftZeilengaLDAPNoOp12RequestControl());

    try
    {
      LDAPResult result = connection.modify(modifyRequest);
      if (result.getResultCode() == ResultCode.NO_OPERATION)
      {
        // The modification would likely have succeeded if the no-op control
        // hadn't been included in the request.
      }
      else
      {
        // The modification would likely have failed if the no-op control
        // hadn't been included in the request.
      }
    }
    catch (LDAPException le)
    {
      // The modification failed even with the no-op control in the request.
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }
}
