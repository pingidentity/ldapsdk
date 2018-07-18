/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the set of authentication types that may appear in log
 * messages about bind operations.
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
public enum BindRequestAuthenticationType
{
  /**
   * The authentication type that will be used for authentication by an internal
   * client.
   */
  INTERNAL,



  /**
   * The authentication type that will be used for SASL authentication.
   */
  SASL,



  /**
   * The authentication type that will be used for simple authentication.
   */
  SIMPLE;



  /**
   * Retrieves the authentication type with the specified name.
   *
   * @param  name  The name of the authentication type to retrieve.  It must not
   *               be {@code null}.
   *
   * @return  The requested authentication type, or {@code null} if no such type
   *          is defined.
   */
  public static BindRequestAuthenticationType forName(final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "internal":
        return INTERNAL;
      case "sasl":
        return SASL;
      case "simple":
        return SIMPLE;
      default:
        return null;
    }
  }
}
