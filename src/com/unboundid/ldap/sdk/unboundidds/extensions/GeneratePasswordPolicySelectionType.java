/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum describes the mechanism that the server should use when selecting
 * the password policy to use (for its password generator and validators) while
 * processing a {@link GeneratePasswordExtendedRequest}.
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
public enum GeneratePasswordPolicySelectionType
{
  /**
   * The selection type that indicates that the server should use the default
   * password policy as defined in the configuration.
   */
  DEFAULT_POLICY((byte) 0x80),



  /**
   * The selection type that indicates that the server should use the password
   * policy that is defined in a specified entry.
   */
  PASSWORD_POLICY_DN((byte) 0x81),



  /**
   * The selection type that indicates that the server should use the password
   * policy that governs a specified entry.
   */
  TARGET_ENTRY_DN((byte) 0x82);



  // The BER type associated with this password policy selection type.
  private final byte berType;



  /**
   * Creates a new password policy selection type with the provided BER type.
   *
   * @param  type  The BER type associated with this password policy selection
   *               type.
   */
  GeneratePasswordPolicySelectionType(final byte type)
  {
    this.berType = type;
  }



  /**
   * Retrieves the BER type that will be used to identify this password policy
   * selection type in a {@link GeneratePasswordExtendedRequest}.
   *
   * @return  The BER type that will be used to identify this password policy
   *          selection type in a generate password extended request.
   */
  public byte getBERType()
  {
    return berType;
  }



  /**
   * Retrieves the password policy selection type with the specified BER type.
   *
   * @param  berType  The BER type for the password policy selection type to
   *                  retrieve.
   *
   * @return  The password policy selection type with the specified BER type,
   *          or {@code null} if there is no selection type with the provided
   *          BER type.
   */
  @Nullable()
  public static GeneratePasswordPolicySelectionType forType(final byte berType)
  {
    for (final GeneratePasswordPolicySelectionType t : values())
    {
      if (t.berType == berType)
      {
        return t;
      }
    }

    return null;
  }
}
