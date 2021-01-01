/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
 * This class is used internally by ExampleCommandLineArgument to provide
 * details about the escaping that needs to be performed on an argument.
 */
@InternalUseOnly
@ThreadSafety(level = ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class QuotingRequirements implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1430038162579028168L;



  // true if and only if the argument needs to be single-quoted on Unix
  private final boolean requiresSingleQuotesOnUnix;

  // true if and only if the argument needs to be double-quoted on Unix
  private final boolean requiresDoubleQuotesOnUnix;

  // true if and only if the argument includes a single-quote
  private final boolean includesSingleQuote;

  // true if and only if the argument includes a double-quote
  private final boolean includesDoubleQuote;



  /**
   * Creates a new instance of the requirements with the provided settings.
   *
   * @param  requiresSingleQuotesOnUnix  {@code true} if the argument requires
   *                                     single-quoting on Unix.
   * @param  requiresDoubleQuotesOnUnix  {@code true} if the argument requires
   *                                     double-quoting on Unix.
   * @param  includesSingleQuote         {@code true} if the argument includes a
   *                                     single-quote.
   * @param  includesDoubleQuote         {@code true} if the argument includes a
   *                                     double-quote.
   */
  QuotingRequirements(final boolean requiresSingleQuotesOnUnix,
                      final boolean requiresDoubleQuotesOnUnix,
                      final boolean includesSingleQuote,
                      final boolean includesDoubleQuote)
  {
    this.requiresSingleQuotesOnUnix = requiresSingleQuotesOnUnix;
    this.requiresDoubleQuotesOnUnix = requiresDoubleQuotesOnUnix;
    this.includesSingleQuote = includesSingleQuote;
    this.includesDoubleQuote = includesDoubleQuote;
  }



  /**
   * Returns {@code true} if the argument requires a single-quoting on Unix.
   *
   * @return  {@code true} if the argument requires a single-quoting on Unix.
   */
  public boolean requiresSingleQuotesOnUnix()
  {
    return requiresSingleQuotesOnUnix;
  }



  /**
   * Returns {@code true} if the argument requires a double-quoting on Unix.
   *
   * @return  {@code true} if the argument requires a double-quoting on Unix.
   */
  public boolean requiresDoubleQuotesOnUnix()
  {
    return requiresDoubleQuotesOnUnix;
  }


  /**
   * Returns {@code true} if the argument includes a single-quote.
   *
   * @return  {@code true} if the argument includes a single-quote.
   */
  public boolean includesSingleQuote()
  {
    return includesSingleQuote;
  }



  /**
   * Returns {@code true} if the argument includes a double-quote.
   *
   * @return  {@code true} if the argument includes a double-quote.
   */
  public boolean includesDoubleQuote()
  {
    return includesDoubleQuote;
  }
}
