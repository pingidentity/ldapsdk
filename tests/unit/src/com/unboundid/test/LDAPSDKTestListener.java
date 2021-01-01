/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import java.io.File;
import java.io.PrintStream;
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
import org.testng.internal.IConfigurationListener;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.NullOutputStream;
import com.unboundid.util.StaticUtils;



/**
 * This class defines a custom test listener that can be used to capture
 * information about tests as they run.
 */
public class LDAPSDKTestListener
       implements ITestListener, IConfigurationListener
{
  // The file to which the test log file is being written.
  private File testLogFile;

  // The number of tests that have failed.
  private int numFailed;

  // The number of tests that have passed;
  private int numPassed;

  // The names and number of tests that have failed.
  private final LinkedHashMap<String,Integer> failedTests;

  // The time processing started on the last class.
  private long lastClassStartTime;

  // A writer that records messages in a log file.
  private PrintStream logWriter;

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
    failedTests        = new LinkedHashMap<>(10);
    logWriter          = NullOutputStream.getPrintStream();
    numFailed          = 0;
    numPassed          = 0;
    testLogFile        = null;
  }



  /**
   * Performs any necessary processing before any tests have started.
   *
   * @param  context  The text context.
   */
  @Override()
  public synchronized void onStart(final ITestContext context)
  {
    try
    {
      final String baseDirString = System.getProperty("basedir");
      if (baseDirString == null)
      {
        throw new AssertionError("basedir is not set");
      }

      final File baseDir = new File(baseDirString);
      final File buildDir = new File(baseDir, "build");
      final File testDir = new File(buildDir, "test");
      final File reportDir = new File(testDir, "report");
      if (! reportDir.exists())
      {
        throw new AssertionError("Test report dir '" +
             reportDir.getAbsolutePath() + "' does not exist.");
      }

      testLogFile = new File(reportDir, "test.log");
      logWriter = new PrintStream(testLogFile);
    }
    catch (final Throwable t)
    {
      throw new RuntimeException(
           "ERROR:  Unable to open test logger:  " +
                StaticUtils.getStackTrace(t),
           t);
    }

    log("     Class       Tests      Tests");
    log("  Time (ms)     Passed     Failed  Test Class Name");
    log("  ---------  ---------  ---------  ------------------------------");

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
  @Override()
  public synchronized void onFinish(final ITestContext context)
  {
    printRightAligned(System.currentTimeMillis() - lastClassStartTime, 11);
    printRightAligned(numPassed, 11);
    printRightAligned(numFailed, 11);
    logWithoutNewline("  ");

    final int dotPos = lastClass.lastIndexOf('.');
    if (dotPos > 0)
    {
      log(lastClass.substring(dotPos+1));
    }
    else
    {
      log(lastClass);
    }

    log();
    log("All tests completed.");

    if (! failedTests.isEmpty())
    {
      log();
      log("The following tests failed:  ");

      for (final String methodName : failedTests.keySet())
      {
        final int count = failedTests.get(methodName);
        if (count == 1)
        {
          log("     " + methodName);
        }
        else
        {
          log("     " + methodName + " (x" + count + ')');
        }
      }
    }

    final List<StackTraceElement[]> unclosedTraces =
         LDAPSDKTestCase.getUnclosedConnectionTraces();
    if (! unclosedTraces.isEmpty())
    {
      log();
      log("***** WARNING:  Unclosed connection(s) detected:");
      for (final StackTraceElement[] e : unclosedTraces)
      {
        log("Creation stack trace:");
        for (int i=1; i < e.length; i++)
        {
          log("     " + e[i].toString());
        }

        log();
      }
    }

    logWriter.close();

    System.err.println();
    System.err.println("Test log results written to '" +
         testLogFile.getAbsolutePath() + "'.");
  }



  /**
   * Performs any necessary processing before a test begins.
   *
   * @param  result  The test result for the test.
   */
  @Override()
  public synchronized void onTestStart(final ITestResult result)
  {
    final IClass testClass = result.getTestClass();
    final String className = testClass.getName();
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
      logWithoutNewline("  ");

      final int dotPos = lastClass.lastIndexOf('.');
      if (dotPos > 0)
      {
        log(lastClass.substring(dotPos+1));
      }
      else
      {
        log(lastClass);
      }

      lastClassStartTime = System.currentTimeMillis();
      lastClass = className;
    }

    // Make sure that the test class is a subclass of LDAPSDKTestCase
    final Class<?> c = testClass.getRealClass();
    if (! (LDAPSDKTestCase.class.isAssignableFrom(c)))
    {
      log();
      log("WARNING:  Test class " + lastClass +
           " does not extend LDAPSDKTestCase");
      log();
    }

    // Make sure that the method has the @Test annotation.
    final ITestNGMethod testMethod = result.getMethod();
    lastMethod = testMethod.getMethodName();

    final Method m = testMethod.getMethod();

    boolean testAnnotationFound = false;
    for (final Annotation a : m.getAnnotations())
    {
      if (a instanceof Test)
      {
        testAnnotationFound = true;
      }
    }

    if (! testAnnotationFound)
    {
      log();
      log("WARNING:  Test method " + lastClass + '.' + lastMethod +
           " does not have a @Test annotation");
      log();
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
  private void printRightAligned(final long number, final int length)
  {
    final String numberStr = String.valueOf(number);
    for (int i=0; i < length - numberStr.length(); i++)
    {
      logWithoutNewline(" ");
    }

    logWithoutNewline(numberStr);
  }



  /**
   * Performs any necessary processing after a test has been skipped.
   *
   * @param  result  The test result for the test.
   */
  @Override()
  public synchronized void onTestSkipped(final ITestResult result)
  {
    log("********** Skipped test " + result.getTestClass().getName() + '.' +
         result.getMethod().getMethodName());
  }



  /**
   * Performs any necessary processing after a test has completed successfully.
   *
   * @param  result  The test result for the test.
   */
  @Override()
  public synchronized void onTestSuccess(final ITestResult result)
  {
    numPassed++;
  }



  /**
   * Performs any necessary processing after a test has failed.
   *
   * @param  result  The test result for the test.
   */
  @Override()
  public synchronized void onTestFailure(final ITestResult result)
  {
    numFailed++;

    final String name = lastClass + '.' + lastMethod;
    if (failedTests.containsKey(name))
    {
      failedTests.put(name, (failedTests.get(name)+1));
    }
    else
    {
      failedTests.put(name, 1);
    }

    log();
    log();
    log();
    log("********** TEST FAILED **********");
    log("Time:  " + new Date());
    log("Test Method:  " + result.getTestClass().getName() +
                       '.' + result.getMethod().getMethodName());
    final Object[] params = result.getParameters();
    if ((params != null) && (params.length > 0))
    {
      log("Parameters: " + Arrays.toString(params));
    }
    logStackTrace(result.getThrowable());
    log();
    log();
    log();
  }



  /**
   * Performs any necessary processing after a test has failed but within an
   * acceptable success percentage.
   *
   * @param  result  The test result for the test.
   */
  @Override()
  public synchronized void onTestFailedButWithinSuccessPercentage(
                                final ITestResult result)
  {
    numFailed++;

    log();
    log();
    log();
    log("********** TEST FAILED WITHIN SUCCESS PERCENTAGE " +
                       "**********");
    log("Test Method:  " + result.getTestClass().getName() +
                       '.' + result.getMethod().getMethodName());
    logStackTrace(result.getThrowable());
    log();
    log();
    log();
  }



  /**
   * Performs any necessary processing after test configuration has completed
   * successfully.
   *
   * @param  result  The test result for the test.
   */
  @Override()
  public synchronized void onConfigurationSuccess(final ITestResult result)
  {
    // No implementation required
  }



  /**
   * Performs any necessary processing after test configuration has failed.
   *
   * @param  result  The test result for the test.
   */
  @Override()
  public void onConfigurationFailure(final ITestResult result)
  {
    numFailed++;

    final String name = result.getTestClass().getName() + '.' +
         result.getMethod().getMethodName();
    if (failedTests.containsKey(name))
    {
      failedTests.put(name, (failedTests.get(name)+1));
    }
    else
    {
      failedTests.put(name, 1);
    }

    log();
    log();
    log();
    log("********** CONFIGURATION FAILED **********");
    log("Time:  " + new Date());
    log("Test Method:  " + result.getTestClass().getName() +
                       '.' + result.getMethod().getMethodName());
    final Object[] params = result.getParameters();
    if ((params != null) && (params.length > 0))
    {
      log("Parameters: " + Arrays.toString(params));
    }
    logStackTrace(result.getThrowable());
    log();
    log();
    log();
  }



  /**
   * Performs any necessary processing after test configuration has been
   * skipped.
   *
   * @param  result  The test result for the test.
   */
  @Override()
  public void onConfigurationSkip(final ITestResult result)
  {
    log("********** Skipped test configuration " +
         result.getTestClass().getName() + '.' +
         result.getMethod().getMethodName());
  }



  /**
   * Writes a blank line to both standard error and to the log file.
   */
  private void log()
  {
    System.err.println();
    logWriter.println();
    logWriter.flush();
  }



  /**
   * Writes the provided message to both standard error and to the log file.
   * The message will be followed by a newline.
   *
   * @param  message  The message to be logged.
   */
  private void log(final String message)
  {
    System.err.println(message);
    logWriter.println(message);
    logWriter.flush();
  }



  /**
   * Writes the provided message to both standard error and to the log file.
   * The message will not be followed by a newline.
   *
   * @param  message  The message to be logged.
   */
  private void logWithoutNewline(final String message)
  {
    System.err.print(message);
    logWriter.print(message);
    logWriter.flush();
  }



  /**
   * Writes a stack trace of the provided {@code Throwable} object to both
   * standard error and oth the log file.
   *
   * @param  t  The {@code Throwable} object to be printed.
   */
  private void logStackTrace(final Throwable t)
  {
    if (t == null)
    {
      return;
    }

    t.printStackTrace();
    t.printStackTrace(logWriter);
  }
}
