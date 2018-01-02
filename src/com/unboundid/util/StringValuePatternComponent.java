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
final class StringValuePatternComponent
      extends ValuePatternComponent
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5948022796724341802L;



  // The string that will be used by this component.
  private final String valueString;



  /**
   * Creates a new string value component with the provided string.
   *
   * @param  valueString  The string that will be used by this component.
   */
  StringValuePatternComponent(final String valueString)
  {
    this.valueString = valueString;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  void append(final StringBuilder buffer)
  {
    buffer.append(valueString);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  boolean supportsBackReference()
  {
    return false;
  }
}
