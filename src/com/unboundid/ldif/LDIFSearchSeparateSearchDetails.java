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
import java.util.Arrays;

import com.unboundid.ldap.listener.SearchEntryParer;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;



/**
 * This class provides a data structure that correlates a set of information
 * needed in the course of maintaining a separate output file per search.
 */
final class LDIFSearchSeparateSearchDetails
{
  // The output file to which the results will be written.
  @NotNull private final File outputFile;

  // The LDAP URL with the associated search criteria.
  @NotNull private final LDAPURL ldapURL;

  // The LDIF writer that will be used to write results to the output file.
  @NotNull private final LDIFWriter ldifWriter;

  // The search entry parer that will be used to pare search results.
  @NotNull private final SearchEntryParer searchEntryParer;



  /**
   * Creates an instance of this search details object with the provided
   * information.
   *
   * @param  ldapURL     The LDAP URL with the associated search criteria.
   * @param  outputFile  The output file to which the results will be written.
   * @param  ldifWriter  The LDIF writer that will be used to write results to
   *                     the output file.
   * @param  schema      The schema to use when paring search result entries.
   */
  LDIFSearchSeparateSearchDetails(@NotNull final LDAPURL ldapURL,
                                  @NotNull final File outputFile,
                                  @NotNull final LDIFWriter ldifWriter,
                                  @Nullable final Schema schema)
  {
    this.ldapURL = ldapURL;
    this.outputFile = outputFile;
    this.ldifWriter = ldifWriter;

    searchEntryParer =
         new SearchEntryParer(Arrays.asList(ldapURL.getAttributes()), schema);
  }



  /**
   * Retrieves the LDAP URL with the associated search criteria.
   *
   * @return  The LDAP URL with the associated search criteria.
   */
  @NotNull()
  LDAPURL getLDAPURL()
  {
    return ldapURL;
  }



  /**
   * Retrieves the output file to which results will be written.
   *
   * @return  The output file to which results will be written.
   */
  @NotNull()
  File getOutputFile()
  {
    return outputFile;
  }



  /**
   * Retrieve the LDIF writer to use to write the results.
   *
   * @return  The LDIF writer to use to write the results.
   */
  @NotNull()
  LDIFWriter getLDIFWriter()
  {
    return ldifWriter;
  }



  /**
   * Retrieves the object that will be used to pare matching entries based on
   * the set of requested attributes.
   *
   * @return  The object that will be used to pare matching entries based on the
   *          set of requested attributes.
   */
  @NotNull()
  SearchEntryParer getSearchEntryParer()
  {
    return searchEntryParer;
  }
}
