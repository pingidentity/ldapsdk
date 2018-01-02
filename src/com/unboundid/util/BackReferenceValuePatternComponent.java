/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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



/**
 * This class defines a string value pattern component, which will always
 * generate the same static text.
 */
final class BackReferenceValuePatternComponent
      extends ValuePatternComponent
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 417294789313497595L;



  // The index of the referenced component.  It will be one-based rather than
  // zero-based.
  private final int index;



  /**
   * Creates a new back-reference component with the specified index.
   *
   * @param  index  The one-based index of the referenced component.
   */
  BackReferenceValuePatternComponent(final int index)
  {
    this.index = index;
  }



  /**
   * Retrieves the one-based index for this back-reference component.
   *
   * @return  The one-based index for this back-reference component.
   */
  int getIndex()
  {
    return index;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  void append(final StringBuilder buffer)
  {
    // This should never be called.
    throw new AssertionError(
         "Unexpected call to BackReferenceValuePatternComponent.append");
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  boolean supportsBackReference()
  {
    return true;
  }
}
