/*
 * Copyright 2015-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2017 UnboundID Corp.
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
package com.unboundid.util.args;



/**
 * This class provides an implementation of an argument value validator that
 * will only accept a provided string value.
 */
public final class TestArgumentValueValidator
       extends ArgumentValueValidator
{
  // The only string that will be acceptable to this argument value validator.
  private final String acceptableString;



  /**
   * Creates a new test argument value validator with the given string.
   *
   * @param  acceptableString  The only string that will be considered
   *                           acceptable.
   */
  public TestArgumentValueValidator(final String acceptableString)
  {
    this.acceptableString = acceptableString;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void validateArgumentValue(final Argument argument,
                                    final String valueString)
         throws ArgumentException
  {
    if (! valueString.equals(acceptableString))
    {
      throw new ArgumentException("The provided string '" + valueString +
           "' does not match the only acceptable string '" + acceptableString +
           "'.");
    }
  }
}
