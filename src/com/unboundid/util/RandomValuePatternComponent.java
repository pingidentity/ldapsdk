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
  private final Random seedRandom;

  // The format string that will be used by the decimal formatter.
  private final String formatString;

  // The decimal format that will be used by this component, if applicable.
  private final ThreadLocal<DecimalFormat> decimalFormat;

  // The random number generator that will be used by this component.
  private final ThreadLocal<Random> random;



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
                              final long seed, final String formatString)
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
    random     = new ThreadLocal<Random>();

    this.formatString = formatString;
    decimalFormat     = new ThreadLocal<DecimalFormat>();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  void append(final StringBuilder buffer)
  {
    Random r = random.get();
    if (r == null)
    {
      r = new Random(seedRandom.nextLong());
      random.set(r);
    }

    final long value = ((r.nextLong() & 0x7FFFFFFF) % span) + lowerBound;
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
