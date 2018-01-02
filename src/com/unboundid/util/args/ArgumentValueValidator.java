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



import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an API that may be used to create argument value
 * validators, which can be used to enforce additional constraints on the values
 * provided to an argument.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class ArgumentValueValidator
{
  /**
   * Examines the value(s) assigned to the provided argument to determine
   * whether they are acceptable.
   *
   * @param  argument     The argument to which the value is being provided.
   * @param  valueString  The string representation of the value to be
   *                      validated.  This value will have already passed any
   *                      normal validation performed by the argument.
   *
   * @throws  ArgumentException  If the provided value is determined to be
   *                             unacceptable.
   */
  public abstract void validateArgumentValue(Argument argument,
                                             String valueString)
         throws ArgumentException;
}
