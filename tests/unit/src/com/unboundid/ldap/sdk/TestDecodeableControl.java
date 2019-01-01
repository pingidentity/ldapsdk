/*
 * Copyright 2009-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2019 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1OctetString;



/**
 * This class provides an instance of a decodeable control that may be used for
 * test purposes.
 */
public class TestDecodeableControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID for this control.
   */
  public static final String OID = "1.2.3.4.5.6.7.8";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID =  2857105351848166747L;



  /**
   * Creates a new instance of this control.
   */
  public TestDecodeableControl()
  {
    super(OID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public TestDecodeableControl decodeControl(final String oid,
                                             final boolean isCritical,
                                             final ASN1OctetString value)
  {
    return new TestDecodeableControl();
  }
}
