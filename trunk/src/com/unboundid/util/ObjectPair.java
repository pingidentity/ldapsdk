/*
 * Copyright 2008-2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2009 UnboundID Corp.
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



/**
 * This class provides a typed pair of objects.  It may be used whenever two
 * objects are required but only one is allowed (e.g., returning two values from
 * a method).
 *
 * @param  <F>  The type of the first object.
 * @param  <S>  The type of the second object.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ObjectPair<F,S>
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8610279945233778440L;



  // The first object in this pair.
  private final F first;

  // The second object in this pair.
  private final S second;



  /**
   * Creates a new object pair with the provided elements.
   *
   * @param  first   The first object in this pair.
   * @param  second  The second object in this pair.
   */
  public ObjectPair(final F first, final S second)
  {
    this.first  = first;
    this.second = second;
  }



  /**
   * Retrieves the first object in  this pair.
   *
   * @return  The first object in this pair.
   */
  public F getFirst()
  {
    return first;
  }



  /**
   * Retrieves the second object in this pair.
   *
   * @return  The second object in this pair.
   */
  public S getSecond()
  {
    return second;
  }
}
