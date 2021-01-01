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
package com.unboundid.ldif;



import java.io.File;
import java.io.IOException;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.EntrySourceException;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.LDAPTestUtils;



/**
 * This class is primarily intended to ensure that code provided in javadoc
 * examples is valid.
 */
public final class ExampleUsagesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the example in the {@code LDIFChangeRecord} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDIFChangeRecordExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection connection = ds.getConnection();

    final File ldifFile = createTempFile(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: test");
    final String pathToLDIFFile = ldifFile.getAbsolutePath();


    /* ----- BEGIN EXAMPLE CODE ----- */
    LDIFReader ldifReader = new LDIFReader(pathToLDIFFile);

    int changesRead = 0;
    int changesProcessed = 0;
    int errorsEncountered = 0;
    while (true)
    {
      LDIFChangeRecord changeRecord;
      try
      {
        changeRecord = ldifReader.readChangeRecord();
        if (changeRecord == null)
        {
          // All changes have been processed.
          break;
        }

        changesRead++;
      }
      catch (LDIFException le)
      {
        errorsEncountered++;
        if (le.mayContinueReading())
        {
          // A recoverable error occurred while attempting to read a change
          // record, at or near line number le.getLineNumber()
          // The change record will be skipped, but we'll try to keep reading
          // from the LDIF file.
          continue;
        }
        else
        {
          // An unrecoverable error occurred while attempting to read a change
          // record, at or near line number le.getLineNumber()
          // No further LDIF processing will be performed.
          break;
        }
      }
      catch (IOException ioe)
      {
        // An I/O error occurred while attempting to read from the LDIF file.
        // No further LDIF processing will be performed.
        errorsEncountered++;
        break;
      }

      // Try to process the change in a directory server.
      LDAPResult operationResult;
      try
      {
        operationResult = changeRecord.processChange(connection);
        // If we got here, then the change should have been processed
        // successfully.
        changesProcessed++;
      }
      catch (LDAPException le)
      {
        // If we got here, then the change attempt failed.
        operationResult = le.toLDAPResult();
        errorsEncountered++;
      }
    }

    ldifReader.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertEquals(changesRead, 1);
    assertEquals(changesProcessed, 1);
    assertEquals(errorsEncountered, 0);
  }



  /**
   * Tests the example in the {@code LDIFEntrySource} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDIFEntrySourceExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    final String pathToLDIFFile = ldifFile.getAbsolutePath();


    /* ----- BEGIN EXAMPLE CODE ----- */
    LDIFEntrySource entrySource =
         new LDIFEntrySource(new LDIFReader(pathToLDIFFile));

    int entriesRead = 0;
    int errorsEncountered = 0;
    try
    {
      while (true)
      {
        try
        {
          Entry entry = entrySource.nextEntry();
          if (entry == null)
          {
            // There are no more entries to be read.
            break;
          }
          else
          {
            // Do something with the entry here.
            entriesRead++;
          }
        }
        catch (EntrySourceException e)
        {
          // Some kind of problem was encountered (e.g., a malformed entry
          // found in the LDIF file, or an I/O error when trying to read).  See
          // if we can continue reading entries.
          errorsEncountered++;
          if (! e.mayContinueReading())
          {
            break;
          }
        }
      }
    }
    finally
    {
      entrySource.close();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    assertEquals(entriesRead, 1);
    assertEquals(errorsEncountered, 0);
  }



  /**
   * Tests the example in the {@code LDIFReader} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDIFReaderExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(false, false);
    final LDAPConnection connection = ds.getConnection();

    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    final String pathToLDIFFile = ldifFile.getAbsolutePath();


    /* ----- BEGIN EXAMPLE CODE ----- */
    LDIFReader ldifReader = new LDIFReader(pathToLDIFFile);

    int entriesRead = 0;
    int entriesAdded = 0;
    int errorsEncountered = 0;
    while (true)
    {
      Entry entry;
      try
      {
        entry = ldifReader.readEntry();
        if (entry == null)
        {
          // All entries have been read.
          break;
        }

        entriesRead++;
      }
      catch (LDIFException le)
      {
        errorsEncountered++;
        if (le.mayContinueReading())
        {
          // A recoverable error occurred while attempting to read a change
          // record, at or near line number le.getLineNumber()
          // The entry will be skipped, but we'll try to keep reading from the
          // LDIF file.
          continue;
        }
        else
        {
          // An unrecoverable error occurred while attempting to read an entry
          // at or near line number le.getLineNumber()
          // No further LDIF processing will be performed.
          break;
        }
      }
      catch (IOException ioe)
      {
        // An I/O error occurred while attempting to read from the LDIF file.
        // No further LDIF processing will be performed.
        errorsEncountered++;
        break;
      }

      LDAPResult addResult;
      try
      {
        addResult = connection.add(entry);
        // If we got here, then the change should have been processed
        // successfully.
        entriesAdded++;
      }
      catch (LDAPException le)
      {
        // If we got here, then the change attempt failed.
        addResult = le.toLDAPResult();
        errorsEncountered++;
      }
    }

    ldifReader.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertEquals(entriesRead, 1);
    assertEquals(entriesAdded, 1);
    assertEquals(errorsEncountered, 0);
  }



  /**
   * Tests the example in the {@code LDIFWriter} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDIFWriterExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection connection = ds.getConnection();
    connection.modify(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: ou",
         "ou: Sales");

    final File ldifFile = createTempFile();
    assertTrue(ldifFile.delete());
    final String pathToLDIF = ldifFile.getAbsolutePath();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Perform a search to find all users who are members of the sales
    // department.
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("ou", "Sales"));
    SearchResult searchResult;
    try
    {
      searchResult = connection.search(searchRequest);
    }
    catch (LDAPSearchException lse)
    {
      searchResult = lse.getSearchResult();
    }
    LDAPTestUtils.assertResultCodeEquals(searchResult, ResultCode.SUCCESS);

    // Write all of the matching entries to LDIF.
    int entriesWritten = 0;
    LDIFWriter ldifWriter = new LDIFWriter(pathToLDIF);
    for (SearchResultEntry entry : searchResult.getSearchEntries())
    {
      ldifWriter.writeEntry(entry);
      entriesWritten++;
    }

    ldifWriter.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertEquals(entriesWritten, 1);
  }
}
