/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.io.File;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides the superclass for all utility test cases.
 */
@Test(sequential=true)
public abstract class SSLTestCase
       extends LDAPSDKTestCase
{
  /**
   * Retrieves the path to a key store in JKS format.
   *
   * @return  The path to a key store in JKS format.
   */
  protected static String getJKSKeyStorePath()
  {
    File resourceDir = new File(System.getProperty("unit.resource.dir"));
    File jksKeystore = new File(resourceDir, "keystore.jks");
    return jksKeystore.getAbsolutePath();
  }



  /**
   * Retrieves the PIN to use to access the JKS key store.
   *
   * @return  The PIN to use to access the JKS key store.
   */
  protected static char[] getJKSKeyStorePIN()
  {
    return "password".toCharArray();
  }



  /**
   * Retrieves the alias of a certificate contained in the JKS key store.
   *
   * @return  The alias of a certificate contained in the JKS key store.
   */
  protected static String getJKSKeyStoreAlias()
  {
    return "test";
  }



  /**
   * Retrieves the path to a key store in PKCS12 format.
   *
   * @return  The path to a key store in PKCS12 format.
   */
  protected static String getPKCS12KeyStorePath()
  {
    File resourceDir = new File(System.getProperty("unit.resource.dir"));
    File pkcs12Keystore = new File(resourceDir, "keystore.p12");
    return pkcs12Keystore.getAbsolutePath();
  }



  /**
   * Retrieves the PIN to use to access the PKCS12 key store.
   *
   * @return  The PIN to use to access the PKCS12 key store.
   */
  protected static char[] getPKCS12KeyStorePIN()
  {
    return "password".toCharArray();
  }



  /**
   * Retrieves the alias of a certificate contained in the PKCS12 key store.
   *
   * @return  The alias of a certificate contained in the PKCS12 key store.
   */
  protected static String getPKCS12KeyStoreAlias()
  {
    return "test";
  }
}
