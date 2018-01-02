/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.util.regex.Pattern;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides an implementation of an argument value validator that is
 * expected to be used with a string argument and ensures that all values for
 * the argument are valid regular expressions.  Note that it does not verify
 * that values match a given regular expression, but that can already be
 * accomplished with the {@link StringArgument#setValueRegex} method.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RegularExpressionArgumentValueValidator
       extends ArgumentValueValidator
{
  /**
   * Creates a new instance of this regular expression argument value validator.
   */
  public RegularExpressionArgumentValueValidator()
  {
    // No implementation is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void validateArgumentValue(final Argument argument,
                                    final String valueString)
         throws ArgumentException
  {
    try
    {
      Pattern.compile(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           ERR_REGEX_VALIDATOR_VALUE_NOT_REGEX.get(valueString,
                argument.getIdentifierString()));
    }
  }



  /**
   * Retrieves a string representation of this argument value validator.
   *
   * @return  A string representation of this argument value validator.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this argument value validator to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("RegularExpressionArgumentValueValidator()");
  }
}
