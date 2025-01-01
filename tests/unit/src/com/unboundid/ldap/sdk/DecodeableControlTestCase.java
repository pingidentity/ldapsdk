/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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



import java.io.File;
import java.lang.reflect.Field;
import java.util.ArrayList;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases to ensure that all decodeable
 * controls defined in the LDAP SDK codebase are properly registered and can be
 * decoded.
 */
public final class DecodeableControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Ensures that all classes that implement the DecodeableControl interface are
   * properly registered with the LDAP SDK out of the box.
   *
   * @param  sdkClass  the class to examine, which may or may not implement the
   *                   DecodeableControl interface.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="sdkClasses")
  public void testAllDecodeableControlsRegistered(final Class<?> sdkClass)
         throws Exception
  {
    boolean isDecodeableControlClass = false;
    final Class<?>[] interfaces = sdkClass.getInterfaces();
    for (final Class<?> c : interfaces)
    {
      if (c.equals(DecodeableControl.class))
      {
        isDecodeableControlClass = true;
        break;
      }
    }

    if (! isDecodeableControlClass)
    {
      return;
    }

    final String oid = getControlOID(sdkClass);
    assertTrue(Control.DECODEABLE_CONTROL_CLASS_NAMES.containsKey(oid),
         "DecodeableControl class " + sdkClass.getName() +
              " is not registered as a DecodeableControl");
  }



  /**
   * Determines the OID for the control defined in the provided class.  It does
   * this by looking at string constants in the class that are either named
   * "OID" or that contain "_OID" or "OID_" in the name.
   *
   * @param  controlClass  The class for which to obtain the OID.
   *
   * @return  The OID for the control defined in the provided class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static String getControlOID(final Class<?> controlClass)
          throws Exception
  {
    String oid = null;
    for (final Field field : controlClass.getDeclaredFields())
    {
      if (! field.getType().equals(String.class))
      {
        continue;
      }

      final String fieldName = field.getName();
      if (fieldName.equals("OID") || fieldName.contains("_OID") ||
           fieldName.contains("OID_"))
      {
        if (oid == null)
        {
          oid = (String) field.get(null);
        }
        else
        {
          fail("Found multiple OID constantss in DecodeableControl class" +
               controlClass.getName());
        }
      }
    }

    if (oid == null)
    {
      fail("Could not determine the OID for DecodeableControl " +
           controlClass.getName());
    }

    return oid;
  }



  /**
   * Retrieves the fully-qualified names of all classes included in the SDK.
   *
   * @return  The fully-qualified names of all classes included in the SDK.
   *
   * @throws  Exception  If a problem occurs during processing.
   */
  @DataProvider(name="sdkClasses")
  public Object[][] getSDKClasses()
         throws Exception
  {
    final File baseDir = new File(System.getProperty("basedir"));
    final File buildDir = new File(baseDir, "build");
    final File classesDir = new File(buildDir, "classes");

    final ArrayList<Class<?>> classList = new ArrayList<Class<?>>();
    findClasses("", classesDir,  classList);

    final Object[][] classes = new Object[classList.size()][1];
    for (int i=0; i < classes.length; i++)
    {
      classes[i][0] = classList.get(i);
    }

    return classes;
  }



  /**
   * Recursively identifies all classes in the provided directory.
   *
   * @param  p  The package name associated with the provided directory.
   * @param  d  The directory to be processed.
   * @param  l  The to which the classes should be added.
   *
   * @throws  Exception  If a problem occurs during processing.
   */
  private static void findClasses(final String p, final File d,
                                  final ArrayList<Class<?>> l)
          throws Exception
  {
    for (final File f : d. listFiles())
    {
      if (f.isDirectory())
      {
        if (p.length() == 0)
        {
          findClasses(f.getName(), f, l);
        }
        else
        {
          findClasses(p + '.' + f.getName(), f, l);
        }
      }
      else if (f.getName().endsWith(".class") &&
               (! f.getName().contains("$")))
      {
        int dotPos = f.getName().lastIndexOf('.');
        String baseName = f.getName().substring(0, dotPos);
        String className = p + '.' + baseName;
        l.add(Class.forName(className));
      }
    }
  }
}
