/*
 * Copyright 2009-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2017 UnboundID Corp.
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
package com.unboundid.ldap.sdk.persist;



import java.util.concurrent.atomic.AtomicInteger;

import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;



/**
 * This class provides an object search listener that may be used for testing
 * purposes.
 */
public class TestObjectSearchListener
       implements ObjectSearchListener<TestOrganizationalUnit>
{
  // The count of valid objects retrieved.
  private final AtomicInteger validCount;

  // The count of invalid objects retrieved.
  private final AtomicInteger invalidCount;

  // The count of references retrieved.
  private final AtomicInteger referenceCount;



  /**
   * Creates a new instance of this class.
   */
  public TestObjectSearchListener()
  {
    validCount     = new AtomicInteger(0);
    invalidCount   = new AtomicInteger(0);
    referenceCount = new AtomicInteger(0);
  }



  /**
   * {@inheritDoc}
   */
  public void objectReturned(final TestOrganizationalUnit o)
  {
    validCount.incrementAndGet();
  }



  /**
   * {@inheritDoc}
   */
  public void unparsableEntryReturned(final SearchResultEntry entry,
                                      final LDAPPersistException exception)
  {
    invalidCount.incrementAndGet();
  }



  /**
   * {@inheritDoc}
   */
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    referenceCount.incrementAndGet();
  }



  /**
   * Retrieves the number of valid objects returned.
   *
   * @return  The number of valid objects returned.
   */
  public int getValidCount()
  {
    return validCount.get();
  }



  /**
   * Retrieves the number of invalid objects returned.
   *
   * @return  The number of invalid objects returned.
   */
  public int getInvalidCount()
  {
    return invalidCount.get();
  }



  /**
   * Retrieves the number of references returned.
   *
   * @return  The number of references returned.
   */
  public int getReferenceCount()
  {
    return referenceCount.get();
  }
}
