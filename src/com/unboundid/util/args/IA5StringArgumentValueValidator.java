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
package com.unboundid.util.args;



import java.io.Serializable;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides an implementation of an argument value validator that
 * ensures that values can be parsed as valid IA5 strings (that is, strings
 * containing only ASCII characters).
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IA5StringArgumentValueValidator
       extends ArgumentValueValidator
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7395996449791650693L;



  // Indicates whether values are allowed to be empty strings.
  private final boolean allowEmptyStrings;



  /**
   * Creates a new IA5 string argument value validator.  Empty strings will not
   * be considered valid.
   */
  public IA5StringArgumentValueValidator()
  {
    this(false);
  }



  /**
   * Creates a new IA5 string argument value validator.
   *
   * @param  allowEmptyStrings  Indicates whether empty strings will be
   *                            considered valid.
   */
  public IA5StringArgumentValueValidator(final boolean allowEmptyStrings)
  {
    this.allowEmptyStrings = allowEmptyStrings;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void validateArgumentValue(@NotNull final Argument argument,
                                    @NotNull final String valueString)
         throws ArgumentException
  {
    final int length = valueString.length();
    if ((length == 0) && (! allowEmptyStrings))
    {
      throw new ArgumentException(ERR_IA5_STRING_VALIDATOR_EMPTY_STRING.get(
           argument.getIdentifierString()));
    }

    for (int i=0; i < length; i++)
    {
      final char c = valueString.charAt(i);
      final int fullByte = ((int) c & 0xFF);
      final int asciiByte = ((int) c & 0x7F);
      if (fullByte != asciiByte)
      {
        throw new ArgumentException(ERR_IA5_STRING_VALIDATOR_ILLEGAL_CHAR.get(
             valueString, argument.getIdentifierString(),
             String.valueOf(c),
             i));
      }
    }
  }



  /**
   * Indicates whether empty strings should be considered valid.
   *
   * @return  {@code true} if empty strings should be considered valid, or
   *          {@code false} if not.
   */
  public boolean allowEmptyStrings()
  {
    return allowEmptyStrings;
  }



  /**
   * Retrieves a string representation of this argument value validator.
   *
   * @return  A string representation of this argument value validator.
   */
  @Override()
  @NotNull()
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
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("IA5StringArgumentValueValidator(allowEmptyStrings=");
    buffer.append(allowEmptyStrings);
    buffer.append(')');
  }
}
