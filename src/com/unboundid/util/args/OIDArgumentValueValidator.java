/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
import java.text.ParseException;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.OID;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides an implementation of an argument value validator that
 * ensures that values can be parsed as valid object identifiers.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class OIDArgumentValueValidator
       extends ArgumentValueValidator
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2195078137238476902L;



  // Indicates whether to perform strict validation.
  private final boolean isStrict;



  /**
   * Creates a new OID address argument value validator that will only accept
   * strictly valid numeric OIDs.
   */
  public OIDArgumentValueValidator()
  {
    this(true);
  }



  /**
   * Creates a new OID address argument value validator that will only accept
   * valid numeric OIDs.
   *
   * @param  isStrict  Indicates whether to perform strict validation.  If this
   *                   is {@code false}, then the validator will only sure that
   *                   each value is a dotted list of digits that does not start
   *                   or end with a period and does not contain two consecutive
   *                   periods.  If this is {@code true}, then it will also
   *                   ensure that it contains at least two components, that the
   *                   value of the first component is not greater than two,
   *                   and that the value of the second component is not greater
   *                   than 39 if the value of the first component is zero or
   *                   one.
   */
  public OIDArgumentValueValidator(final boolean isStrict)
  {
    this.isStrict = isStrict;
  }



  /**
   * Indicates whether this validator is configured to operate in strict mode.
   * If it not operating in strict mode, then it will only ensure that each
   * value is is a dotted list of digits that does not start or end with a
   * period and does not contain two consecutive periods.  If it is strict, then
   * it will also ensure that it contains at least two components, that the
   * value of the first component is not greater than two, and that the value of
   * the second component is not greater than 39 if the value of the first
   * component is zero or one.
   *
   * @return  {@code true} if this validator is configured to operate in strict
   *          mode, or {@code false} if not.
   */
  public boolean isStrict()
  {
    return isStrict;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void validateArgumentValue(@NotNull final Argument argument,
                                    @NotNull final String valueString)
         throws ArgumentException
  {
    try
    {
      OID.parseNumericOID(valueString, isStrict);
    }
    catch (final ParseException e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           ERR_OID_VALIDATOR_INVALID_VALUE.get(argument.getIdentifierString(),
                e.getMessage()),
           e);
    }
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
    buffer.append("OIDArgumentValueValidator(isStrict=");
    buffer.append(isStrict);
    buffer.append(')');
  }
}
