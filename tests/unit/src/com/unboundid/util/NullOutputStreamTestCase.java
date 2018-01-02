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



import org.testng.annotations.Test;



/**
 * This class provides test coverage for the {@code NullOutputStream} class.
 */
public class NullOutputStreamTestCase
       extends UtilTestCase
{
  /**
   * Test all methods in the {@code NullOutputStream} class to ensure they do
   * not throw exceptions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullOutputStream()
         throws Exception
  {
    NullOutputStream outputStream = new NullOutputStream();
    assertNotNull(outputStream);

    outputStream.write("foo".getBytes());

    outputStream.write("foo".getBytes(), 0, 3);

    outputStream.write('f');

    outputStream.flush();

    outputStream.close();

    assertNotNull(NullOutputStream.getInstance());

    assertNotNull(NullOutputStream.getPrintStream());
  }
}
