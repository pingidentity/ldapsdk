/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import com.unboundid.util.LDAPSDKException;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines an exception that may be thrown if a problem occurs while
 * trying to access an entry in an entry source (e.g., because the entry source
 * is no longer available, because an entry could not be parsed, or because the
 * next element returned was a search result reference rather than a search
 * result entry).
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class EntrySourceException
       extends LDAPSDKException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -9221149707074845318L;



  // Indicates whether it is possible to continue attempting to iterate through
  // subsequent entries.
  private final boolean mayContinueReading;



  /**
   * Creates a new entry source exception with the provided information.
   *
   * @param  mayContinueReading  Indicates whether it is possible to continue
   *                             attempting to iterate through subsequent
   *                             entries in the entry source.
   * @param  cause               The underlying exception that triggered this
   *                             exception.  It must not be {@code null}.
   */
  public EntrySourceException(final boolean mayContinueReading,
                              @Nullable final Throwable cause)
  {
    super(StaticUtils.getExceptionMessage(cause), cause);

    Validator.ensureNotNull(cause);

    this.mayContinueReading = mayContinueReading;
  }



  /**
   * Creates a new entry source exception with the provided information.
   *
   * @param  mayContinueReading  Indicates whether it is possible to continue
   *                             attempting to iterate through subsequent
   *                             entries in the entry source.
   * @param  message             A message explaining the problem that occurred.
   *                             It must not be {@code null}.
   * @param  cause               The underlying exception that triggered this
   *                             exception.  It must not be {@code null}.
   */
  public EntrySourceException(final boolean mayContinueReading,
                              @NotNull final String message,
                              @Nullable final Throwable cause)
  {
    super(message, cause);

    Validator.ensureNotNull(message, cause);

    this.mayContinueReading = mayContinueReading;
  }



  /**
   * Indicates whether it is possible to continue attempting to iterate through
   * subsequent entries in the entry source.
   *
   * @return  {@code true} if it is possible to continue attempting to read from
   *          the entry source, or {@code false} if it is not possible to
   *          continue.
   */
  public final boolean mayContinueReading()
  {
    return mayContinueReading;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("EntrySourceException(message='");
    buffer.append(getMessage());
    buffer.append("', mayContinueReading=");
    buffer.append(mayContinueReading);
    buffer.append(", cause='");
    buffer.append(StaticUtils.getExceptionMessage(getCause()));
    buffer.append("')");
  }
}
