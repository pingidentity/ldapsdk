/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.Serializable;
import java.util.Comparator;



/**
 * This class provides a test comparator for {@code Long} objects.
 */
public final class TestLongComparator
       implements Comparator<Long>, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3110287000275534560L;



  /**
   * Creates a new instance of this comparator.
   */
  public TestLongComparator()
  {
    // No implementation required.
  }



  /**
   * Compares the provided values.
   *
   * @param  l1  The first value to compare.
   * @param  l2  The second value to compare.
   *
   * @return  The result of the comparison
   */
  @Override()
  public int compare(final Long l1, final Long l2)
  {
    return l1.compareTo(l2);
  }



  /**
   * Retrieves a hash code for this class.
   *
   * @return  A hash code for this class.
   */
  @Override()
  public int hashCode()
  {
    return 0;
  }



  /**
   * Indicates whether the provided object is equal to this comparator.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if it is equal, or {@code false} if not.
   */
  @Override()
  public boolean equals(final Object o)
  {
    return ((o != null) && (o instanceof TestLongComparator));
  }
}
