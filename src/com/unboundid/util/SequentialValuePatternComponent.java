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
import java.util.concurrent.atomic.AtomicLong;



/**
 * This class defines a sequential numeric value pattern component, which will
 * generate numeric values in sequential order, optionally using an increment
 * and format string.
 */
final class SequentialValuePatternComponent
      extends ValuePatternComponent
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3553865579642557953L;



  // The next value to return.
  @NotNull private final AtomicLong nextValue;

  // The increment for this component.
  private final long increment;

  // The lower bound for this component.
  private final long lowerBound;

  // The upper bound for this component.
  private final long upperBound;

  // The format string that will be used by the decimal formatter.
  @Nullable private final String formatString;

  // The decimal format that will be used by this component, if applicable.
  @NotNull private final ThreadLocal<DecimalFormat> decimalFormat;



  /**
   * Creates a new sequential numeric value pattern component with the provided
   * information.
   *
   * @param  lowerBound    The lower bound that will be used by this component.
   * @param  upperBound    The upper bound that will be used by this component.
   * @param  increment     The increment that will be used by this component.
   * @param  formatString  The format string that will be used by this
   *                       component, if any.
   */
  SequentialValuePatternComponent(final long lowerBound, final long upperBound,
                                  final long increment,
                                  @Nullable final String formatString)
  {
    if (lowerBound == upperBound)
    {
      this.lowerBound = lowerBound;
      this.upperBound = upperBound;
      this.increment  = 0L;
    }
    else if (lowerBound > upperBound)
    {
      this.lowerBound = upperBound;
      this.upperBound = lowerBound;

      if (Math.abs(increment) > (lowerBound - upperBound))
      {
        this.increment = 0L;
      }
      else
      {
        this.increment  = -1L * increment;
      }
    }
    else
    {
      this.lowerBound = lowerBound;
      this.upperBound = upperBound;

      if (Math.abs(increment) > (upperBound - lowerBound))
      {
        this.increment = 0L;
      }
      else
      {
        this.increment = increment;
      }
    }

    this.formatString = formatString;
    decimalFormat     = new ThreadLocal<>();
    nextValue         = new AtomicLong(lowerBound);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  void append(@NotNull final StringBuilder buffer)
  {
    long value = nextValue.getAndAdd(increment);
    if (value > upperBound)
    {
      if (nextValue.compareAndSet(value+increment, lowerBound))
      {
        value = nextValue.getAndAdd(increment);
      }
      else
      {
        while (true)
        {
          final long v = nextValue.get();
          if ((v < upperBound) || nextValue.compareAndSet(v, lowerBound))
          {
            value = nextValue.getAndAdd(increment);
            break;
          }
        }
      }
    }
    else if (value < lowerBound)
    {
      if (nextValue.compareAndSet(value+increment, upperBound))
      {
        value = nextValue.getAndAdd(increment);
      }
      else
      {
        while (true)
        {
          final long v = nextValue.get();
          if ((v > lowerBound) || nextValue.compareAndSet(v, upperBound))
          {
            value = nextValue.getAndAdd(increment);
            break;
          }
        }
      }
    }

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
