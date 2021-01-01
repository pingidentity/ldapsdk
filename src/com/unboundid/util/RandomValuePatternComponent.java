/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import java.text.DecimalFormat;
import java.util.Random;



/**
 * This class defines a random numeric value pattern component, which will
 * generate numeric values chosen randomly from a given range, optionally using
 * a format string.
 */
final class RandomValuePatternComponent
      extends ValuePatternComponent
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -670528378158953667L;



  // The lower bound for generated values.
  private final long lowerBound;

  // The span for generated values.
  private final long span;

  // The random number generator that will be used to seed the thread-local
  // generators.
  @NotNull private final Random seedRandom;

  // The format string that will be used by the decimal formatter.
  @Nullable private final String formatString;

  // The decimal format that will be used by this component, if applicable.
  @NotNull private final ThreadLocal<DecimalFormat> decimalFormat;

  // The random number generator that will be used by this component.
  @NotNull private final ThreadLocal<Random> random;



  /**
   * Creates a new random numeric value pattern component with the provided
   * information.
   *
   * @param  lowerBound    The lower bound that will be used by this component.
   * @param  upperBound    The upper bound that will be used by this component.
   * @param  seed          The value that will be used to seed the initial
   *                       random number generator.
   * @param  formatString  The format string that will be used by this
   *                       component, if any.
   */
  RandomValuePatternComponent(final long lowerBound, final long upperBound,
                              final long seed,
                              @Nullable final String formatString)
  {
    if (lowerBound == upperBound)
    {
      this.lowerBound = lowerBound;

      span = 1L;
    }
    else if (lowerBound > upperBound)
    {
      this.lowerBound = upperBound;

      span = lowerBound - upperBound + 1;
    }
    else
    {
      this.lowerBound = lowerBound;

      span = upperBound - lowerBound + 1;
    }

    seedRandom = new Random(seed);
    random     = new ThreadLocal<>();

    this.formatString = formatString;
    decimalFormat     = new ThreadLocal<>();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  void append(@NotNull final StringBuilder buffer)
  {
    Random r = random.get();
    if (r == null)
    {
      r = new Random(seedRandom.nextLong());
      random.set(r);
    }

    final long value = ((r.nextLong() & 0x7FFF_FFFF) % span) + lowerBound;
    if (formatString == null)
    {
      buffer.append(value);
    }
    else
    {
      DecimalFormat f = decimalFormat.get();
      if (f == null)
      {
        f = new DecimalFormat(formatString);
        decimalFormat.set(f);
      }

      buffer.append(f.format(value));
    }
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
