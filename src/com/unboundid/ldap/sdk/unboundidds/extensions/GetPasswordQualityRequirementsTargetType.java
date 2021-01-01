/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum specifies the modes in which the get password quality requirements
 * extended operation may determine the type of password update operation that
 * will be performed and the way in which the server should determine which
 * password policy to use in order to obtain the password quality requirements.
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
public enum GetPasswordQualityRequirementsTargetType
{
  /**
   * Indicates that the Directory Server should return the password quality
   * requirements that the server's default password policy will impose for an
   * add operation.
   */
  ADD_WITH_DEFAULT_PASSWORD_POLICY((byte) 0x80),



  /**
   * Indicates that the Directory Server should return the password quality
   * requirements that the server will impose for an add operation for an entry
   * governed by a specific password policy.  The password policy will be
   * identified by the DN of the entry containing the password policy
   * definition.
   */
  ADD_WITH_SPECIFIED_PASSWORD_POLICY((byte) 0x81),



  /**
   * Indicates that the Directory Server should return the password quality
   * requirements that the server will impose for a self password change for
   * the authorization identity used for the get password quality requirements
   * extended request.
   */
  SELF_CHANGE_FOR_AUTHORIZATION_IDENTITY((byte) 0x82),



  /**
   * Indicates that the Directory Server should return the password quality
   * requirements that the server will impose for a self password change for a
   * specific user, identified by DN.
   */
  SELF_CHANGE_FOR_SPECIFIED_USER((byte) 0x83),



  /**
   * Indicates that the Directory Server should return the password quality
   * requirements that the server will impose for an administrative password
   * reset for a specific user, identified by DN.
   */
  ADMINISTRATIVE_RESET_FOR_SPECIFIED_USER((byte) 0x84);



  // The BER type that will be used for this target type in an encoded get
  // password quality requirements extended request.
  private final byte berType;



  /**
   * Creates a new get password quality requirements target type with the
   * specified BER type.
   *
   * @param  berType  The BER type that will be used for this target type in an
   *                  encoded get password quality requirements extended
   *                  request.
   */
  GetPasswordQualityRequirementsTargetType(final byte berType)
  {
    this.berType = berType;
  }



  /**
   * Retrieves the BER type that will be used for this target type in an encoded
   * get password quality requirements extended request.
   *
   * @return  The BER type that will be used for this target type in an encoded
   *          get password quality requirements extended request.
   */
  public byte getBERType()
  {
    return berType;
  }



  /**
   * Retrieves the get password quality requirements target type with the
   * specified BER type.
   *
   * @param  berType  The BER type for the target type to retrieve.
   *
   * @return  The get password quality requirements target type with the
   *          specified BER type, or {@code null} if there is no target type
   *          with the specified BER type.
   */
  @Nullable()
  public static GetPasswordQualityRequirementsTargetType forBERType(
                     final byte berType)
  {
    for (final GetPasswordQualityRequirementsTargetType t : values())
    {
      if (t.berType == berType)
      {
        return t;
      }
    }

    return null;
  }



  /**
   * Retrieves the get password quality requirements target type with the
   * specified name.
   *
   * @param  name  The name of the get password quality requirements target type
   *               to retrieve.  It must not be {@code null}.
   *
   * @return  The requested get password quality requirements target type, or
   *          {@code null} if no such type is defined.
   */
  @Nullable()
  public static GetPasswordQualityRequirementsTargetType forName(
                     @NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "addwithdefaultpasswordpolicy":
      case "add-with-default-password-policy":
      case "add_with_default_password_policy":
        return ADD_WITH_DEFAULT_PASSWORD_POLICY;
      case "addwithspecifiedpasswordpolicy":
      case "add-with-specified-password-policy":
      case "add_with_specified_password_policy":
        return ADD_WITH_SPECIFIED_PASSWORD_POLICY;
      case "selfchangeforauthorizationidentity":
      case "self-change-for-authorization-identity":
      case "self_change_for_authorization_identity":
        return SELF_CHANGE_FOR_AUTHORIZATION_IDENTITY;
      case "selfchangeforspecifieduser":
      case "self-change-for-specified-user":
      case "self_change_for_specified_user":
        return SELF_CHANGE_FOR_SPECIFIED_USER;
      case "administrativeresetforspecifieduser":
      case "administrative-reset-for-specified-user":
      case "administrative_reset_for_specified_user":
        return ADMINISTRATIVE_RESET_FOR_SPECIFIED_USER;
      default:
        return null;
    }
  }
}
