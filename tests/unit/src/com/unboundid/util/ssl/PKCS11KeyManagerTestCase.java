/*
 * Copyright 2008-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import org.testng.annotations.Test;



/**
 * This class provides test coverage for the PKCS11KeyManager class.
 * Note that this is just intended to provide some level of coverage, since we
 * cannot rely on the existence of a PKCS#11 keystore.
 */
public class PKCS11KeyManagerTestCase
       extends SSLTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    try
    {
      new PKCS11KeyManager("doesntmatter".toCharArray(), "alsodoesntmatter");
    }
    catch (Exception e)
    {
      // This is OK, since we're just trying to get some coverage in this class.
    }
  }
}
