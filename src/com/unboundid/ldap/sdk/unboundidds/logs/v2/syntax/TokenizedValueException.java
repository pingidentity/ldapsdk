/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an exception that may be used to indicate that a log field
 * value cannot be parsed in accordance with the associated syntax because
 * either the entire value or one or more of its components have been tokenized.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TokenizedValueException
       extends LogSyntaxException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5528040979425471701L;



  /**
   * Creates a new instance of this exception with the provided message.
   *
   * @param  message  The message to use for this exception.
   */
  public TokenizedValueException(@NotNull final String message)
  {
    super(message);
  }



  /**
   * Creates a new instance of this exception with the provided message and
   * cause.
   *
   * @param  message  The message to use for this exception.
   * @param  cause    The underlying cause for this exception.  It may be
   *                  {@code null} if no cause is available.
   */
  public TokenizedValueException(@NotNull final String message,
                                 @Nullable final Throwable cause)
  {
    super(message, cause);
  }
}
