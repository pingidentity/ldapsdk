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



import static com.unboundid.util.StaticUtils.*;



/**
 * This enumeration defines a set of debugging types that are used by the LDAP
 * SDK.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum DebugType
{
  /**
   * The debug type that will be used for debugging information about ASN.1
   * elements written to or read from a directory server.
   */
  ASN1("asn1"),



  /**
   * The debug type that will be used for debugging information about
   * connection establishment and termination.
   */
  CONNECT("connect"),



  /**
   * The debug type that will be used for debugging information about
   * exceptions that are caught.
   */
  EXCEPTION("exception"),



  /**
   * The debug type that will be used for debugging information about LDAP
   * requests sent to or received from a directory server.
   */
  LDAP("ldap"),



  /**
   * The debug type that will be used for debugging information about LDIF
   * entries or change records read or written.
   */
  LDIF("ldif"),



  /**
   * The debug type that will be used for information about monitor entry
   * parsing.
   */
  MONITOR("monitor"),



  /**
   * The debug type that will be used for information about coding errors or
   * other types of incorrect uses of the LDAP SDK.
   */
  CODING_ERROR("coding-error"),



  /**
   * The debug type that will be used for debug messages not applicable to any
   * of the other categories.
   */
  OTHER("other");



  // The name for this debug type.
  private final String name;



  /**
   * Creates a new debug type with the specified name.
   *
   * @param  name  The name for this debug type.  It should be in all lowercase
   *               characters.
   */
  DebugType(final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the name for this debug type.
   *
   * @return  The name for this debug type.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the debug type with the specified name.
   *
   * @param  name  The name of the debug type to retrieve.
   *
   * @return  The requested debug type, or {@code null} if there is no such
   *          debug type.
   */
  public static DebugType forName(final String name)
  {
    final String lowerName = toLowerCase(name);

    if (lowerName.equals("asn1"))
    {
      return ASN1;
    }
    else if (lowerName.equals("connect"))
    {
      return CONNECT;
    }
    else if (lowerName.equals("exception"))
    {
      return EXCEPTION;
    }
    else if (lowerName.equals("ldap"))
    {
      return LDAP;
    }
    else if (lowerName.equals("ldif"))
    {
      return LDIF;
    }
    else if (lowerName.equals("monitor"))
    {
      return MONITOR;
    }
    else if (lowerName.equals("coding-error"))
    {
      return CODING_ERROR;
    }
    else if (lowerName.equals("other"))
    {
      return OTHER;
    }

    return null;
  }



  /**
   * Retrieves a comma-delimited list of the defined debug type names.
   *
   * @return  A comma-delimited list of the defined debug type names.
   */
  public static String getTypeNameList()
  {
    final StringBuilder buffer = new StringBuilder();

    final DebugType[] types = DebugType.values();
    for (int i=0; i < types.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append(types[i].getName());
    }

    return buffer.toString();
  }



  /**
   * Retrieves a string representation of this debug type.
   *
   * @return  A string representation of this debug type.
   */
  @Override()
  public String toString()
  {
    return name;
  }
}
