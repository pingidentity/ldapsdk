/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure which represents an LDAP extended
 * response.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the {@link ExtendedResult} class
 * should be used instead.
 */
@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPExtendedResponse
       extends LDAPResponse
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7956345950545720834L;



  // The extended result for this LDAP extended response.
  private final ExtendedResult extendedResult;



  /**
   * Creates a new LDAP extended response from the provided
   * {@link ExtendedResult} object.
   *
   * @param  extendedResult  The {@code ExtendedResult} to use to create this
   *                         LDAP extended response.
   */
  public LDAPExtendedResponse(final ExtendedResult extendedResult)
  {
    super(extendedResult);

    this.extendedResult = extendedResult;
  }



  /**
   * Retrieves the OID for this LDAP extended response, if any.
   *
   * @return  The OID for this LDAP extended response, or {@code null} if there
   *          is none.
   */
  public String getID()
  {
    return extendedResult.getOID();
  }



  /**
   * Retrieves the value for this LDAP extended response, if any.
   *
   * @return  The value for this LDAP extended response, or {@code null} if
   *          there is none.
   */
  public byte[] getValue()
  {
    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      return null;
    }
    else
    {
      return value.getValue();
    }
  }



  /**
   * Retrieves an {@link ExtendedResult} object that is the equivalent of this
   * LDAP extended response.
   *
   * @return  An {@code ExtendedResult} object that is the equivalent of this
   *          LDAP extended response.
   */
  public final ExtendedResult toExtendedResult()
  {
    return extendedResult;
  }



  /**
   * Retrieves a string representation of this LDAP extended response.
   *
   * @return  A string representation of this LDAP extended response.
   */
  @Override()
  public String toString()
  {
    return extendedResult.toString();
  }
}
