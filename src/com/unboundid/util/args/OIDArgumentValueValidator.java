/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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



import java.util.List;

import com.unboundid.util.NotMutable;
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
{
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
  public void validateArgumentValue(final Argument argument,
                                    final String valueString)
         throws ArgumentException
  {
    if (valueString.isEmpty())
    {
      throw new ArgumentException(ERR_OID_VALIDATOR_EMPTY.get(valueString,
           argument.getIdentifierString()));
    }

    if (valueString.startsWith(".") || valueString.endsWith("."))
    {
      throw new ArgumentException(
           ERR_OID_VALIDATOR_STARTS_OR_ENDS_WITH_PERIOD.get(valueString,
                argument.getIdentifierString()));
    }

    if (valueString.contains(".."))
    {
      throw new ArgumentException(
           ERR_OID_VALIDATOR_CONSECUTIVE_PERIODS.get(valueString,
                argument.getIdentifierString()));
    }

    final OID oid = new OID(valueString);
    if (! oid.isValidNumericOID())
    {
      throw new ArgumentException(
           ERR_OID_VALIDATOR_ILLEGAL_CHARACTER.get(valueString,
                argument.getIdentifierString()));
    }

    if (! isStrict)
    {
      return;
    }

    final List<Integer> components = oid.getComponents();
    if (components.size() < 2)
    {
      throw new ArgumentException(
           ERR_OID_VALIDATOR_NOT_ENOUGH_COMPONENTS.get(valueString,
                argument.getIdentifierString()));
    }

    final int firstComponent = components.get(0);
    final int secondComponent = components.get(1);
    switch (firstComponent)
    {
      case 0:
      case 1:
        if (secondComponent > 39)
        {
          throw new ArgumentException(
               ERR_OID_VALIDATOR_ILLEGAL_SECOND_COMPONENT.get(valueString,
                    argument.getIdentifierString()));
        }
        break;

      case 2:
        // We don't need to do any more validation.
        break;

      default:
        // Invalid value for the first component.
        throw new ArgumentException(
             ERR_OID_VALIDATOR_ILLEGAL_FIRST_COMPONENT.get(valueString,
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
    buffer.append("OIDArgumentValueValidator(isStrict=");
    buffer.append(isStrict);
    buffer.append(')');
  }
}
