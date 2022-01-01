/*
 * Copyright 2021-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2022 Ping Identity Corporation
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
 * Copyright (C) 2021-2022 Ping Identity Corporation
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



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the types of channel binding that may be used in
 * conjunction with the GSSAPI SASL mechanism.  Note that channel binding
 * support is dependent upon the underlying JVM and may not be available in all
 * cases.
 *
 * @see  GSSAPIBindRequest
 * @see  GSSAPIBindRequestProperties
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum GSSAPIChannelBindingType
{
  /**
   * The channel binding type that indicates that no channel binding should be
   * used.
   */
  NONE("none"),



  /**
   * The channel binding type that indicates that TLS server end-point channel
   * binding should be used.
   */
  TLS_SERVER_END_POINT("tls-server-end-point");



  // The name for this channel binding type.
  @NotNull private final String name;



  /**
   * Creates a new GSSAPI bind request channel binding type value with the
   * provided name.
   *
   * @param  name  The name to use for this channel binding type.  It must not
   *               be {@code null].
   */
  GSSAPIChannelBindingType(@NotNull final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the name for this GSSAPI channel binding type.
   *
   * @return  The name for this GSSAPI channel binding type.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the GSSAPI channel binding type with the specified name.
   *
   * @param  name  The name of the GSSAPI channel binding type to retrieve.  It
   *               must not be {@code null}.
   *
   * @return  The requested channel binding type, or {@code null} if no channel
   *          binding type is defined with the provided name.
   */
  @Nullable()
  public static GSSAPIChannelBindingType forName(
              @NotNull final String name)
  {
    final String convertedName =
         StaticUtils.toLowerCase(name).replace('_', '-');
    for (final GSSAPIChannelBindingType t : values())
    {
      if (t.name.equals(convertedName))
      {
        return t;
      }
    }

    return null;
  }
}
