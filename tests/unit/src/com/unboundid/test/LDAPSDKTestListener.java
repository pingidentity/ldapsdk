/*
 * Copyright 2008-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 UnboundID Corp.
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
package com.unboundid.test;



import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Arrays;

import org.testng.IClass;
import org.testng.ITestContext;
import org.testng.ITestListener;
import org.testng.ITestNGMethod;
import org.testng.ITestResult;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class defines a custom test listener that can be used to capture
 * information about tests as they run.
 */
public class LDAPSDKTestListener
       implements ITestListener
{
  // The number of tests that have failed.
  private int numFailed;

  // The number of tests that have passed;
  private int numPassed;

  // The names and number of tests that have failed.
  private final LinkedHashMap<String,Integer> failedTests;

  // The time processing started on the last class.
  private long lastClassStartTime;

  // The name of the last class run.
  private String lastClass;

  // The name of the last method run.
  private String lastMethod;



  /**
   * Creates a new instance of this LDAP SDK test listener.
   */
  public LDAPSDKTestListener()
  {
    lastClassStartTime = System.currentTimeMillis();
    lastClass          = null;
    lastMethod         = null;
    failedTests        = new LinkedHashMap<String,Integer>();
  }



  /**
   * Performs any necessary processing before any tests have started.
   *
   * @param  context  The text context.
   */
  public synchronized void onStart(final ITestContext context)
  {
    System.err.println("     Class       Tests      Tests");
    System.err.println("  Time (ms)     Passed     Failed  " +
                       "Test Class Name");
    System.err.println("  ---------  ---------  ---------  " +
                       "------------------------------");

    // Sometimes the output gets muddled when System.out and System.err are
    // going to different streams.  On Windows (at least), this makes the
    // final output hard to understand since TestNG is writing to System.out
    // and we're writing to System.err.
    System.setOut(System.err);
  }



  /**
   * Performs any necessary processing after all tests have completed.
   *
   * @param  context  The text context.
   */
  public synchronized void onFinish(final ITestContext context)
  {
    printRightAligned(System.currentTimeMillis() - lastClassStartTime, 11);
    printRightAligned(numPassed, 11);
    printRightAligned(numFailed, 11);
    System.err.print("  ");

    int dotPos = lastClass.lastIndexOf('.');
    if (dotPos > 0)
    {
      System.err.println(lastClass.substring(dotPos+1));
    }
    else
    {
      System.err.println(lastClass);
    }

    System.err.println();
    System.err.println("All tests completed.");

    if (! failedTests.isEmpty())
    {
      System.err.println();
      System.err.println("The following tests failed:  ");

      for (String methodName : failedTests.keySet())
      {
        int count = failedTests.get(methodName);
        if (count == 1)
        {
          System.err.println("     " + methodName);
        }
        else
        {
          System.err.println("     " + methodName + " (x" + count + ')');
        }
      }
    }

    List<StackTraceElement[]> unclosedTraces =
         LDAPSDKTestCase.getUnclosedConnectionTraces();
    if (! unclosedTraces.isEmpty())
    {
      System.err.println();
      System.err.println("***** WARNING:  Unclosed connection(s) detected:");
      for (StackTraceElement[] e : unclosedTraces)
      {
        System.err.println("Creation stack trace:");
        for (int i=1; i < e.length; i++)
        {
          System.err.println("     " + e[i].toString());
        }

        System.err.println();
      }
    }
  }



  /**
   * Performs any necessary processing before a test begins.
   *
   * @param  result  The test result for the test.
   */
  public synchronized void onTestStart(final ITestResult result)
  {
    IClass testClass = result.getTestClass();
    String className = testClass.getName();
    if (lastClass == null)
    {
      lastClassStartTime = System.currentTimeMillis();
      lastClass = className;
    }
    else if (! lastClass.equals(className))
    {
      printRightAligned(System.currentTimeMillis() - lastClassStartTime, 11);
      printRightAligned(numPassed, 11);
      printRightAligned(numFailed, 11);
      System.err.print("  ");

      int dotPos = lastClass.lastIndexOf('.');
      if (dotPos > 0)
      {
        System.err.println(lastClass.substring(dotPos+1));
      }
      else
      {
        System.err.println(lastClass);
      }

      lastClassStartTime = System.currentTimeMillis();
      lastClass = className;
    }

    // Make sure that the test class is a subclass of LDAPSDKTestCase
    Class<?> c = testClass.getRealClass();
    if (! (LDAPSDKTestCase.class.isAssignableFrom(c)))
    {
      System.err.println();
      System.err.println("WARNING:  Test class " + lastClass +
           " does not extend LDAPSDKTestCase");
      System.err.println();
    }

    // Make sure that the method has the @Test annotation.
    ITestNGMethod testMethod = result.getMethod();
    lastMethod = testMethod.getMethodName();

    Method m = testMethod.getMethod();

    boolean testAnnotationFound = false;
    for (Annotation a : m.getAnnotations())
    {
      if (a instanceof Test)
      {
        testAnnotationFound = true;
      }
    }

    if (! testAnnotationFound)
    {
      System.err.println();
      System.err.println("WARNING:  Test method " + lastClass + '.' +
           lastMethod + " does not have a @Test annotation");
      System.err.println();
    }
  }



  /**
   * Prints the provided number so that it is right aligned in the specified
   * number of spaces.  It will be padded with leading spaces so that the
   * total length is equal to {@code length}.
   *
   * @param  number  The number to be printed.
   * @param  length  The expected length of the resulting string.
   */
  private static void printRightAligned(final long number, final int length)
  {
    String numberStr = String.valueOf(number);
    for (int i=0; i < length - numberStr.length(); i++)
    {
      System.err.print(' ');
    }

    System.err.print(numberStr);
  }



  /**
   * Performs any necessary processing after a test has been skipped.
   *
   * @param  result  The test result for the test.
   */
  public synchronized void onTestSkipped(final ITestResult result)
  {
    System.err.println("********** Skipped test " +
                       result.getTestClass().getName() + '.' +
                       result.getMethod().getMethodName());
  }



  /**
   * Performs any necessary processing after a test has completed successfully.
   *
   * @param  result  The test result for the test.
   */
  public synchronized void onTestSuccess(final ITestResult result)
  {
    numPassed++;
  }



  /**
   * Performs any necessary processing after a test has failed.
   *
   * @param  result  The test result for the test.
   */
  public synchronized void onTestFailure(final ITestResult result)
  {
    numFailed++;

    String name = lastClass + '.' + lastMethod;
    if (failedTests.containsKey(name))
    {
      failedTests.put(name, (failedTests.get(name)+1));
    }
    else
    {
      failedTests.put(name, 1);
    }

    System.err.println();
    System.err.println();
    System.err.println();
    System.err.println("********** TEST FAILED **********");
    System.err.println("Time:  " + new Date());
    System.err.println("Test Method:  " + result.getTestClass().getName() +
                       '.' + result.getMethod().getMethodName());
    Object[] params = result.getParameters();
    if ((params != null) && (params.length > 0))
    {
      System.err.println("Parameters: " + Arrays.toString(params));
    }
    result.getThrowable().printStackTrace();
    System.err.println();
    System.err.println();
    System.err.println();
  }



  /**
   * Performs any necessary processing after a test has failed but within an
   * acceptable success percentage.
   *
   * @param  result  The test result for the test.
   */
  public synchronized void onTestFailedButWithinSuccessPercentage(
                                final ITestResult result)
  {
    numFailed++;

    System.err.println();
    System.err.println();
    System.err.println();
    System.err.println("********** TEST FAILED WITHIN SUCCESS PERCENTAGE " +
                       "**********");
    System.err.println("Test Method:  " + result.getTestClass().getName() +
                       '.' + result.getMethod().getMethodName());
    result.getThrowable().printStackTrace();
    System.err.println();
    System.err.println();
    System.err.println();
  }
}
