/*
 * Copyright 2007-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.Serializable;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a method that may be implemented by controls that may
 * be included in the response from a directory server.  The LDAP SDK will
 * maintain a mapping between response control OIDs and the decodeable control
 * classes that may be used to attempt to decode them.  If a control cannot be
 * decoded using this interface and an exception is thrown, then it will be
 * treated as a generic control.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface DecodeableControl
       extends Serializable
{
  /**
   * Creates a new instance of this decodeable control from the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @return  The decoded representation of this control.
   *
   * @throws  LDAPException  If the provided information cannot be decoded as a
   *                         valid instance of this decodeable control.
   */
  Control decodeControl(String oid, boolean isCritical, ASN1OctetString value)
          throws LDAPException;
}
