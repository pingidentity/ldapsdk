/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
import java.util.Date;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides an implementation of an argument value validator that
 * ensures that values must be timestamps (parsable by the
 * {@link TimestampArgument} class) within a specified time range.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TimestampRangeArgumentValueValidator
       extends ArgumentValueValidator
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7248120077176469324L;



  // The most recent timestamp value that will be accepted.
  @Nullable private final Date mostRecentAllowedDate;

  // The oldest timestamp value that will be accepted.
  @Nullable private final Date oldestAllowedDate;



  /**
   * Creates a new validator that will ensure that timestamp values are within
   * the specified time range.
   *
   * @param  oldestAllowedDate      The oldest timestamp that will be accepted
   *                                by this validator.  It may be {@code null}
   *                                if any timestamp older than the provided
   *                                {@code mostRecentAllowedDate} will be
   *                                permitted.
   * @param  mostRecentAllowedDate  The most recent timestamp that will be
   *                                accepted by this validator.  It may be
   *                                {@code null} if any timestamp more recent
   *                                than the provided {@code oldestAllowedDate}
   *                                will be permitted.
   */
  public TimestampRangeArgumentValueValidator(
              @Nullable final Date oldestAllowedDate,
              @Nullable final Date mostRecentAllowedDate)
  {
    this.oldestAllowedDate = oldestAllowedDate;
    this.mostRecentAllowedDate = mostRecentAllowedDate;
  }



  /**
   * Retrieves the oldest allowed date value that will be permitted by this
   * validator.
   *
   * @return  The oldest allowed date value that will be permitted by this
   *          validator, or {@code null} if any timestamp older than the
   *          most recent allowed date will be permitted.
   */
  @Nullable()
  public Date getOldestAllowedDate()
  {
    return oldestAllowedDate;
  }



  /**
   * Retrieves the most recent allowed date value that will be permitted by this
   * validator.
   *
   * @return  The most recent allowed date value that will be permitted by this
   *          validator, or {@code null} if any timestamp newer than the oldest
   *          allowed date will be permitted.
   */
  @Nullable()
  public Date getMostRecentAllowedDate()
  {
    return mostRecentAllowedDate;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void validateArgumentValue(@NotNull final Argument argument,
                                    @NotNull final String valueString)
         throws ArgumentException
  {
    // Ensure that the value can be parsed as a valid timestamp.
    final Date parsedDate;
    try
    {
      parsedDate = TimestampArgument.parseTimestamp(valueString);
    }
    catch (final Exception e)
    {
      throw new ArgumentException(
           ERR_TIMESTAMP_VALUE_NOT_TIMESTAMP.get(valueString,
                argument.getIdentifierString()),
           e);
    }

    final long parsedTime = parsedDate.getTime();
    if ((oldestAllowedDate != null) &&
        (parsedTime < oldestAllowedDate.getTime()))
    {
      throw new ArgumentException(ERR_TIMESTAMP_RANGE_VALIDATOR_TOO_OLD.get(
           valueString, argument.getIdentifierString(),
           StaticUtils.encodeGeneralizedTime(oldestAllowedDate)));
    }

    if ((mostRecentAllowedDate != null) &&
        (parsedTime > mostRecentAllowedDate.getTime()))
    {
      throw new ArgumentException(ERR_TIMESTAMP_RANGE_VALIDATOR_TOO_NEW.get(
           valueString, argument.getIdentifierString(),
           StaticUtils.encodeGeneralizedTime(mostRecentAllowedDate)));
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
    buffer.append("TimestampRangeArgumentValueValidator(");

    if (oldestAllowedDate != null)
    {
      buffer.append("oldestAllowedDate='");
      buffer.append(StaticUtils.encodeGeneralizedTime(oldestAllowedDate));
      buffer.append('\'');

      if (mostRecentAllowedDate != null)
      {
        buffer.append(", mostRecentAllowedDate='");
        buffer.append(StaticUtils.encodeGeneralizedTime(mostRecentAllowedDate));
        buffer.append('\'');
      }
    }
    else if (mostRecentAllowedDate != null)
    {
      buffer.append("mostRecentAllowedDate='");
      buffer.append(StaticUtils.encodeGeneralizedTime(mostRecentAllowedDate));
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
