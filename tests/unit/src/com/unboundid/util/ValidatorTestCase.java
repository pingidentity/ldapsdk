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
package com.unboundid.util;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the Validator class.
 */
public class ValidatorTestCase
       extends UtilTestCase
{
  /**
   * Tests the {@code ensureNotNull} method variant that takes a single
   * argument.
   *
   * @param  o1          The first test object.
   * @param  shouldFail  Indicates whether the test should fail.
   */
  @Test(dataProvider = "testEnsureNotNullElements1")
  public void testEnsureNotNull1(Object o1, boolean shouldFail)
  {
    boolean failed;

    try
    {
      Validator.ensureNotNull(o1);
      failed = false;
    }
    catch (LDAPSDKUsageException lue)
    {
      failed = true;
    }

    assertEquals(failed, shouldFail);
  }



  /**
   * Tests the {@code ensureNotNull} method variant that takes a single
   * argument and a custom message.
   *
   * @param  o1          The first test object.
   * @param  shouldFail  Indicates whether the test should fail.
   */
  @Test(dataProvider = "testEnsureNotNullElements1")
  public void testEnsureNotNullWithMessage(Object o1, boolean shouldFail)
  {
    boolean failed;

    try
    {
      Validator.ensureNotNullWithMessage(o1, "o1 should not be null.");
      failed = false;
    }
    catch (LDAPSDKUsageException lue)
    {
      failed = true;
    }

    assertEquals(failed, shouldFail);
  }



  /**
   * Tests the {@code ensureNotNull} method variant that takes two arguments.
   *
   * @param  o1          The first test object.
   * @param  o2          The second test object.
   * @param  shouldFail  Indicates whether the test should fail.
   */
  @Test(dataProvider = "testEnsureNotNullElements2")
  public void testEnsureNotNull2(Object o1, Object o2, boolean shouldFail)
  {
    boolean failed;

    try
    {
      Validator.ensureNotNull(o1, o2);
      failed = false;
    }
    catch (LDAPSDKUsageException lue)
    {
      failed = true;
    }

    assertEquals(failed, shouldFail);
  }



  /**
   * Tests the {@code ensureNotNull} method variant that takes three arguments.
   *
   * @param  o1          The first test object.
   * @param  o2          The second test object.
   * @param  o3          The third test object.
   * @param  shouldFail  Indicates whether the test should fail.
   */
  @Test(dataProvider = "testEnsureNotNullElements3")
  public void testEnsureNotNull3(Object o1, Object o2, Object o3,
                                 boolean shouldFail)
  {
    boolean failed;

    try
    {
      Validator.ensureNotNull(o1, o2, o3);
      failed = false;
    }
    catch (LDAPSDKUsageException lue)
    {
      failed = true;
    }

    assertEquals(failed, shouldFail);
  }



  /**
   * Tests the {@code ensureNotNull} method variant that takes four arguments.
   *
   * @param  o1          The first test object.
   * @param  o2          The second test object.
   * @param  o3          The third test object.
   * @param  o4          The fourth test object.
   * @param  shouldFail  Indicates whether the test should fail.
   */
  @Test(dataProvider = "testEnsureNotNullElements4")
  public void testEnsureNotNull4(Object o1, Object o2, Object o3, Object o4,
                                 boolean shouldFail)
  {
    boolean failed;

    try
    {
      Validator.ensureNotNull(o1, o2, o3, o4);
      failed = false;
    }
    catch (LDAPSDKUsageException lue)
    {
      failed = true;
    }

    assertEquals(failed, shouldFail);
  }



  /**
   * Tests the {@code ensureNotNull} method variant that takes five arguments.
   *
   * @param  o1          The first test object.
   * @param  o2          The second test object.
   * @param  o3          The third test object.
   * @param  o4          The fourth test object.
   * @param  o5          The fifth test object.
   * @param  shouldFail  Indicates whether the test should fail.
   */
  @Test(dataProvider = "testEnsureNotNullElements5")
  public void testEnsureNotNull5(Object o1, Object o2, Object o3, Object o4,
                                 Object o5, boolean shouldFail)
  {
    boolean failed;

    try
    {
      Validator.ensureNotNull(o1, o2, o3, o4, o5);
      failed = false;
    }
    catch (LDAPSDKUsageException lue)
    {
      failed = true;
    }

    assertEquals(failed, shouldFail);
  }



  /**
   * Tests the behavior of the [@code ensureNotNullOrEmpty} method for
   * collections.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnsureCollectionNotNullOrEmpty()
         throws Exception
  {
    for (final Collection<?> c :
         Arrays.<Collection<?>>asList(null, Collections.emptyList(),
              Collections.emptySet(), new ArrayList<String>(0)))
    {
      try
      {
        Validator.ensureNotNullOrEmpty(c);
        fail("Expected an exception from a null or empty collection.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }

      try
      {
        Validator.ensureNotNullOrEmpty(c, "This is a custom message.");
        fail("Expected an exception from a null or empty collection.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }
    }

    for (final Collection<?> c :
         Arrays.asList(Collections.singletonList("foo"),
              Collections.singleton("bar"),
              Arrays.asList("one", "two", "three")))
    {
      Validator.ensureNotNullOrEmpty(c);

      Validator.ensureNotNullOrEmpty(c, "This is a custom message.");
    }
  }



  /**
   * Tests the behavior of the [@code ensureNotNullOrEmpty} method for maps.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnsureMapNotNullOrEmpty()
         throws Exception
  {
    for (final Map<?,?> m :
         Arrays.<Map<?,?>>asList(null, Collections.emptyMap(),
              new HashMap<String,String>(0)))
    {
      try
      {
        Validator.ensureNotNullOrEmpty(m);
        fail("Expected an exception from a null or empty map.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }

      try
      {
        Validator.ensureNotNullOrEmpty(m, "This is a custom message.");
        fail("Expected an exception from a null or empty map.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }
    }


    final HashMap<String,String> m1 = new HashMap<>(1);
    m1.put("a", "one");

    final HashMap<String,String> m2 = new HashMap<>(2);
    m2.put("b", "two");
    m2.put("c", "three");

    for (final Map<?,?> m :
         Arrays.asList(Collections.singletonMap("foo", "bar"), m1, m2))
    {
      Validator.ensureNotNullOrEmpty(m);

      Validator.ensureNotNullOrEmpty(m, "This is a custom message.");
    }
  }



  /**
   * Tests the behavior of the [@code ensureNotNullOrEmpty} method for arrays.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnsureArrayNotNullOrEmpty()
         throws Exception
  {
    final Object[] nullObjectArray = null;
    for (final Object[] a :
         Arrays.asList(nullObjectArray, new Object[0], StaticUtils.NO_STRINGS,
              StaticUtils.NO_CONTROLS, new Object[0][], new byte[0][]))
    {
      try
      {
        Validator.ensureNotNullOrEmpty(a);
        fail("Expected an exception from a null or empty object array.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }

      try
      {
        Validator.ensureNotNullOrEmpty(a, "This is a custom message.");
        fail("Expected an exception from a null or empty object array.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }
    }

    final byte[] nullByteArray = null;
    for (final byte[] a : Arrays.asList(nullByteArray, StaticUtils.NO_BYTES))
    {
      try
      {
        Validator.ensureNotNullOrEmpty(a);
        fail("Expected an exception from a null or empty byte array.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }

      try
      {
        Validator.ensureNotNullOrEmpty(a, "This is a custom message.");
        fail("Expected an exception from a null or empty byte array.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }
    }

    final char[] nullCharArray = null;
    for (final char[] a : Arrays.asList(nullCharArray, StaticUtils.NO_CHARS))
    {
      try
      {
        Validator.ensureNotNullOrEmpty(a);
        fail("Expected an exception from a null or empty char array.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }

      try
      {
        Validator.ensureNotNullOrEmpty(a, "This is a custom message.");
        fail("Expected an exception from a null or empty char array.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }
    }

    final int[] nullIntArray = null;
    for (final int[] a : Arrays.asList(nullIntArray, new int[0]))
    {
      try
      {
        Validator.ensureNotNullOrEmpty(a);
        fail("Expected an exception from a null or empty int array.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }

      try
      {
        Validator.ensureNotNullOrEmpty(a, "This is a custom message.");
        fail("Expected an exception from a null or empty int array.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }
    }

    final long[] nullLongArray = null;
    for (final long[] a : Arrays.asList(nullLongArray, new long[0]))
    {
      try
      {
        Validator.ensureNotNullOrEmpty(a);
        fail("Expected an exception from a null or empty long array.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }

      try
      {
        Validator.ensureNotNullOrEmpty(a, "This is a custom message.");
        fail("Expected an exception from a null or empty long array.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }
    }

    for (final Object[] a :
         Arrays.asList(new Object[] { "foo", "bar", "baz" },
                       new String[] { "a", "b", "c" }))
    {
      Validator.ensureNotNullOrEmpty(a);

      Validator.ensureNotNullOrEmpty(a, "This is a custom message.");
    }

    for (final byte[] a :
         Arrays.asList(StaticUtils.byteArray(1),
              StaticUtils.byteArray(2, 3, 4)))
    {
      Validator.ensureNotNullOrEmpty(a);

      Validator.ensureNotNullOrEmpty(a, "This is a custom message.");
    }

    for (final char[] a : Arrays.asList("a".toCharArray(), "bcd".toCharArray()))
    {
      Validator.ensureNotNullOrEmpty(a);

      Validator.ensureNotNullOrEmpty(a, "This is a custom message.");
    }

    for (final int[] a : Arrays.asList(new int[] { 1 }, new int[] { 2, 3, 4 }))
    {
      Validator.ensureNotNullOrEmpty(a);

      Validator.ensureNotNullOrEmpty(a, "This is a custom message.");
    }

    for (final long[] a :
         Arrays.asList(new long[] { 1 }, new long[] { 2, 3, 4 }))
    {
      Validator.ensureNotNullOrEmpty(a);

      Validator.ensureNotNullOrEmpty(a, "This is a custom message.");
    }
  }



  /**
   * Tests the behavior of the [@code ensureNotNullOrEmpty} method for
   * character sequences.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnsureCharSequenceNotNullOrEmpty()
         throws Exception
  {
    for (final CharSequence s :
         Arrays.<CharSequence>asList(null, "", new StringBuilder()))
    {
      try
      {
        Validator.ensureNotNullOrEmpty(s);
        fail("Expected an exception from a null or empty collection.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }

      try
      {
        Validator.ensureNotNullOrEmpty(s, "This is a custom message.");
        fail("Expected an exception from a null or empty collection.");
      }
      catch (final LDAPSDKUsageException e)
      {
        // This was expected.
      }
    }

    for (final CharSequence s : Arrays.asList("foo", new StringBuilder("bar")))
    {
      Validator.ensureNotNullOrEmpty(s);

      Validator.ensureNotNullOrEmpty(s, "This is a custom message.");
    }
  }



  /**
   * Tests the {@code ensureTrue} method with a {@code true} condition.
   */
  @Test()
  public void testEnsureTrueTrue()
  {
    Validator.ensureTrue(true);
  }



  /**
   * Tests the {@code ensureTrue} method with a {@code true} condition and a
   * custom message.
   */
  @Test()
  public void testEnsureTrueTrueCustomMessage()
  {
    Validator.ensureTrue(true, "custom message");
  }



  /**
   * Tests the {@code ensureTrue} method with a {@code false} condition.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEnsureTrueFalse()
  {
    Validator.ensureTrue(false);
  }



  /**
   * Tests the {@code ensureTrue} method with a {@code false} condition and a
   * custom message.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEnsureTrueFalseCustomMessage()
  {
    Validator.ensureTrue(false, "custom message");
  }



  /**
   * Tests the {@code ensureFalse} method with a {@code false} condition.
   */
  @Test()
  public void testEnsureFalseFalse()
  {
    Validator.ensureFalse(false);
  }



  /**
   * Tests the {@code ensureFalse} method with a {@code false} condition and a
   * custom message.
   */
  @Test()
  public void testEnsureFalseFalseCustomMessage()
  {
    Validator.ensureFalse(false, "custom message");
  }



  /**
   * Tests the {@code ensureFalse} method with a {@code true} condition.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEnsureFalseTrue()
  {
    Validator.ensureFalse(true);
  }



  /**
   * Tests the {@code ensureFalse} method with a {@code true} condition and a
   * custom message.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEnsureFalseTrueCustomMessage()
  {
    Validator.ensureFalse(true, "custom message");
  }



  /**
   * Tests the {@code violation} method with a message but no cause.
   */
  @Test()
  public void testViolationWithoutCause()
  {
    final String message = "This is the message.";

    try
    {
      Validator.violation(message);
      fail("Expected an exception when calling Validator.violation with no " +
           "cause");
    }
    catch (final LDAPSDKUsageException e)
    {
      assertNotNull(e.getMessage());
      assertEquals(e.getMessage(), message);

      assertNull(e.getCause());
    }

    try
    {
      Validator.violation(message, null);
      fail("Expected an exception when calling Validator.violation with a " +
           "null cause");
    }
    catch (final LDAPSDKUsageException e)
    {
      assertNotNull(e.getMessage());
      assertEquals(e.getMessage(), message);

      assertNull(e.getCause());
    }

    final RuntimeException cause = new RuntimeException();
    try
    {
      Validator.violation(message, cause);
      fail("Expected an exception when calling Validator.violation with a " +
           "non-null cause");
    }
    catch (final LDAPSDKUsageException e)
    {
      assertNotNull(e.getMessage());
      assertEquals(e.getMessage(), message);

      assertNotNull(e.getCause());
      assertEquals(e.getCause(), cause);
    }
  }



  /**
   * Provides a set of test elements to use when testing the
   * {@code ensureNotNull} method variant that takes a single argument.
   *
   * @return  A set of test elements to use when testing the
   *          {@code ensureNotNull} method variant that takes a single argument.
   */
  @DataProvider(name = "testEnsureNotNullElements1")
  public Object[][] getTestEnsureNotNullElements1()
  {
    return new Object[][]
    {
      new Object[] { "a", false },
      new Object[] { null, true }
    };
  }



  /**
   * Provides a set of test elements to use when testing the
   * {@code ensureNotNull} method variant that takes two arguments.
   *
   * @return  A set of test elements to use when testing the
   *          {@code ensureNotNull} method variant that takes two arguments.
   */
  @DataProvider(name = "testEnsureNotNullElements2")
  public Object[][] getTestEnsureNotNullElements2()
  {
    return new Object[][]
    {
      new Object[] { "a", "b", false },
      new Object[] { null, "b", true },
      new Object[] { "a", null, true },
      new Object[] { null, null, true }
    };
  }



  /**
   * Provides a set of test elements to use when testing the
   * {@code ensureNotNull} method variant that takes three arguments.
   *
   * @return  A set of test elements to use when testing the
   *          {@code ensureNotNull} method variant that takes three arguments.
   */
  @DataProvider(name = "testEnsureNotNullElements3")
  public Object[][] getTestEnsureNotNullElements3()
  {
    return new Object[][]
    {
      new Object[] { "a", "b", "c", false },
      new Object[] { null, "b", "c", true },
      new Object[] { "a", null, "c", true },
      new Object[] { "a", "b", null, true },
      new Object[] { null, null, "c", true },
      new Object[] { null, "b", null, true },
      new Object[] { "a", null, null, true },
      new Object[] { null, null, null, true }
    };
  }



  /**
   * Provides a set of test elements to use when testing the
   * {@code ensureNotNull} method variant that takes four arguments.
   *
   * @return  A set of test elements to use when testing the
   *          {@code ensureNotNull} method variant that takes four arguments.
   */
  @DataProvider(name = "testEnsureNotNullElements4")
  public Object[][] getTestEnsureNotNullElements4()
  {
    return new Object[][]
    {
      new Object[] { "a", "b", "c", "d", false },
      new Object[] { null, "b", "c", "d", true },
      new Object[] { "a", null, "c", "d", true },
      new Object[] { "a", "b", null, "d", true },
      new Object[] { null, null, "c", "d", true },
      new Object[] { null, "b", null, "d", true },
      new Object[] { "a", null, null, "d", true },
      new Object[] { null, null, null, "d", true },
      new Object[] { "a", "b", "c", null, true},
      new Object[] { null, "b", "c", null, true },
      new Object[] { "a", null, "c", null, true },
      new Object[] { "a", "b", null, null, true },
      new Object[] { null, null, "c", null, true },
      new Object[] { null, "b", null, null, true },
      new Object[] { "a", null, null, null, true },
      new Object[] { null, null, null, null, true }
    };
  }



  /**
   * Provides a set of test elements to use when testing the
   * {@code ensureNotNull} method variant that takes five arguments.
   *
   * @return  A set of test elements to use when testing the
   *          {@code ensureNotNull} method variant that takes five arguments.
   */
  @DataProvider(name = "testEnsureNotNullElements5")
  public Object[][] getTestEnsureNotNullElements5()
  {
    return new Object[][]
    {
      new Object[] { "a", "b", "c", "d", "e", false },
      new Object[] { null, "b", "c", "d", "e", true },
      new Object[] { "a", null, "c", "d", "e", true },
      new Object[] { "a", "b", null, "d", "e", true },
      new Object[] { null, null, "c", "d", "e", true },
      new Object[] { null, "b", null, "d", "e", true },
      new Object[] { "a", null, null, "d", "e", true },
      new Object[] { null, null, null, "d", "e", true },
      new Object[] { "a", "b", "c", null, "e", true},
      new Object[] { null, "b", "c", null, "e", true },
      new Object[] { "a", null, "c", null, "e", true },
      new Object[] { "a", "b", null, null, "e", true },
      new Object[] { null, null, "c", null, "e", true },
      new Object[] { null, "b", null, null, "e", true },
      new Object[] { "a", null, null, null, "e", true },
      new Object[] { null, null, null, null, "e", true },
      new Object[] { "a", "b", "c", "d", null, true },
      new Object[] { null, "b", "c", "d", null, true },
      new Object[] { "a", null, "c", "d", null, true },
      new Object[] { "a", "b", null, "d", null, true },
      new Object[] { null, null, "c", "d", null, true },
      new Object[] { null, "b", null, "d", null, true },
      new Object[] { "a", null, null, "d", null, true },
      new Object[] { null, null, null, "d", null, true },
      new Object[] { "a", "b", "c", null, null, true},
      new Object[] { null, "b", "c", null, null, true },
      new Object[] { "a", null, "c", null, null, true },
      new Object[] { "a", "b", null, null, null, true },
      new Object[] { null, null, "c", null, null, true },
      new Object[] { null, "b", null, null, null, true },
      new Object[] { "a", null, null, null, null, true },
      new Object[] { null, null, null, null, null, true }
    };
  }
}
