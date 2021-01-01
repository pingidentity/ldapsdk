/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.examples.Base64Tool;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.ObjectPair;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.NullOutputStream;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a set of test cases for the {@code ToolInvocationLogger}
 * and its associated {@code ToolInvocationLogDetails} and
 * {@code ToolInvocationShutdownHook} classes.
 */
public final class ToolInvocationLoggerTestCase
        extends LDAPSDKTestCase
{
  // A temporary root directory for test configurations.
  private File temporaryDirectory = null;

  // The default directory in which the logging properties file will be located.
  private File configDir = null;

  // The default directory in which the log file will be located.
  private File logsToolsDir = null;

  // The initial value for the instance root property.
  private String initialInstanceRootProperty = null;



  /**
   * Performs the necessary setup to run the tests.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    initialInstanceRootProperty = System.getProperty(
         ToolInvocationLogger.PROPERTY_TEST_INSTANCE_ROOT);

    temporaryDirectory = createTempDir();
    configDir = StaticUtils.constructPath(temporaryDirectory, "config");
    assertTrue(configDir.mkdirs());
    logsToolsDir =
         StaticUtils.constructPath(temporaryDirectory, "logs", "tools");
    assertTrue(logsToolsDir.mkdirs());
    System.setProperty(ToolInvocationLogger.PROPERTY_TEST_INSTANCE_ROOT,
         temporaryDirectory.getAbsolutePath());
  }



  /**
   * Cleans up after testing has completed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    if (initialInstanceRootProperty == null)
    {
      System.clearProperty(ToolInvocationLogger.PROPERTY_TEST_INSTANCE_ROOT);
    }
    else
    {
      System.setProperty(ToolInvocationLogger.PROPERTY_TEST_INSTANCE_ROOT,
           initialInstanceRootProperty);
    }
  }



  /**
   * Tests error handling, specifically when properties file can't be read.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testErrorHandling()
         throws Exception
  {
    try
    {
      final Path badLogPropFile = new File(configDir,
           "tool-invocation-logging.properties").toPath();

      final Set<StandardOpenOption> options = EnumSet.of(
           StandardOpenOption.CREATE, // Create the file if it doesn't exist.
           StandardOpenOption.APPEND, // Append to file if it already exists.
           StandardOpenOption.DSYNC); // Synchronously flush file on writing.
      final Set<PosixFilePermission> perms = EnumSet.of(
           PosixFilePermission.OWNER_WRITE); // Grant owner write access.
      final FileAttribute<Set<PosixFilePermission>> attr =
           PosixFilePermissions.asFileAttribute(perms);

      final FileChannel fileChannel =
           FileChannel.open(badLogPropFile, options, attr);
      fileChannel.write(ByteBuffer.wrap(new byte[0]));

      final ByteArrayOutputStream stream = new ByteArrayOutputStream();
      final PrintStream out = new PrintStream(stream);

      final ToolInvocationLogDetails logDetails =
           ToolInvocationLogger.getLogMessageDetails("testtool", true, out);

      final ArrayList<ObjectPair<String, String>> emptyArgs = new ArrayList<>();

      ToolInvocationLogger.logLaunchMessage(
           logDetails, emptyArgs, emptyArgs, badLogPropFile.toString());

      assertFalse(stream.size() == 0);
    }
    catch (final Exception e)
    {
      throw e;
    }
    finally
    {
      deletePropertiesFile();
    }
  }



  /**
   * Tests handling of nonsense system properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonsenseSystemProperties()
         throws Exception
  {
    try
    {
      System.setProperty(ToolInvocationLogger.PROPERTY_TEST_INSTANCE_ROOT,
           "A/folder/that/doesn't/exist".replace('/', File.separatorChar));

      final ByteArrayOutputStream stream = new ByteArrayOutputStream();
      final PrintStream out = new PrintStream(stream);

      final ToolInvocationLogDetails logDetails =
           ToolInvocationLogger.getLogMessageDetails("tool", true, out);

      final ArrayList<ObjectPair<String, String>> emptyArgs = new ArrayList<>();

      ToolInvocationLogger.logLaunchMessage(logDetails, emptyArgs, emptyArgs,
           "");

      assertEquals(stream.size(), 0);
      assertFalse(logDetails.logInvocation());
    }
    catch (final Exception e)
    {
      throw e;
    }
    finally
    {
      deletePropertiesFile();
      System.setProperty(ToolInvocationLogger.PROPERTY_TEST_INSTANCE_ROOT,
           temporaryDirectory.getAbsolutePath());
    }
  }



  /**
   * Tests handling of nonsense properties from file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonsenseFileProperties()
         throws Exception
  {
    try
    {
      writeToPropertiesFile(
           "ldapmodify.log-file-path=logs/tools/modify.log".replace('/',
                File.separatorChar));

      // Misspelling of false is intentional.
      writeToPropertiesFile("ldapmodify.include-in-default-log=flase");

      final ToolInvocationLogDetails logDetails =
           ToolInvocationLogger.getLogMessageDetails("ldapmodify", true,
                NullOutputStream.getPrintStream());
      assertEquals(logDetails.getLogFiles().size(), 2);
    }
    catch (final Exception e)
    {
      throw e;
    }
    finally
    {
      deletePropertiesFile();
    }
  }



  /**
   * Tests handling of nonsense paths written in the property file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonsenseFilePaths()
         throws Exception
  {
    try
    {
      writeToPropertiesFile(
           "ldapmodify.log-file-path=" + logsToolsDir.getAbsolutePath());
      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      PrintStream out = new PrintStream(stream);
      ToolInvocationLogDetails logDetails =
           ToolInvocationLogger.getLogMessageDetails("ldapmodify", true, out);
      assertFalse(stream.size() == 0);

      stream = new ByteArrayOutputStream();
      out = new PrintStream(stream);
      writeToPropertiesFile(
           "ldapmodify.log-file-path=/this/is/a/nonsense/path".replace('/',
                File.separatorChar));
      logDetails =
           ToolInvocationLogger.getLogMessageDetails("ldapmodify", true, out);
      assertFalse(stream.size() == 0);
    }
    finally
    {
      deletePropertiesFile();
    }
  }



  /**
   * Tests handling of outputting special characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testASCIIPrinting()
         throws Exception
  {
    final ToolInvocationLogDetails logDetails =
         ToolInvocationLogger.getLogMessageDetails("ldapmodify", true,
              NullOutputStream.getPrintStream());

    ToolInvocationLogger.logCompletionMessage(logDetails, 0, "\t\n");

    final String log = readLog(new File(logsToolsDir, "tool-invocation.log"));
    assertTrue(log.contains("\\09\\0a"));
  }



  /**
   * Tests error handling if we cannot obtain an exclusive lock on the log file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLockFileHandling()
         throws Exception
  {
    FileLock lock = null;
    FileChannel channel = null;
    try
    {
      final File logFile = new File(logsToolsDir, "tool-invocation.log");
      channel = new RandomAccessFile(logFile, "rw").getChannel();
      lock = channel.tryLock();

      final ToolInvocationLogDetails logDetails =
           ToolInvocationLogger.getLogMessageDetails("ldapmodify", true,
                NullOutputStream.getPrintStream());

      ToolInvocationLogger.logCompletionMessage(
              logDetails, 0, "This line should never be logged.");

      final String log = readLog(new File(logsToolsDir, "tool-invocation.log"));
      assertFalse(log.contains("This line should never be logged"));
    }
    finally
    {
      lock.release();
      channel.close();
    }
  }



  /**
   * Tests the creation of the {@code ToolInvocationLogDetails} object with no
   * given properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLoggerDefault()
         throws Exception
  {
    try
    {
      final ToolInvocationLogDetails logDetails =
           ToolInvocationLogger.getLogMessageDetails("ldapmodify", true,
                NullOutputStream.getPrintStream());

      assertNotNull(logDetails.getCommandName());
      assertEquals(logDetails.getCommandName(), "ldapmodify");
      assertNotNull(logDetails.toString());
      assertTrue(logDetails.toString().contains("ldapmodify"));

      assertEquals(logDetails.getLogFiles().size(), 1);
      for (final File f : logDetails.getLogFiles())
      {
        // Tests for the default log file's correct default location and name.
        assertTrue(f.getAbsolutePath().endsWith(
             "logs/tools/tool-invocation.log".replace('/',
                  File.separatorChar)));
      }
    }
    catch (final Exception e)
    {
      throw e;
    }
    finally
    {
      deletePropertiesFile();
    }
  }



  /**
   * Tests the creation of the {@code ToolInvocationLogDetails} object with
   * given properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateLoggerWithProperties()
         throws Exception
  {
    try
    {
      // Test handling of an empty properties file.
      writeToPropertiesFile();
      ToolInvocationLogDetails logDetails =
           ToolInvocationLogger.getLogMessageDetails("ldapmodify", true,
                NullOutputStream.getPrintStream());
      for (final File f : logDetails.getLogFiles())
      {
        assertTrue(f.getAbsolutePath().endsWith("tool-invocation.log"));
      }

      writeToPropertiesFile("default.log-file-path=" +
           logsToolsDir.getAbsolutePath() +
           "/custom-name.log".replace('/', File.separatorChar));
      logDetails = ToolInvocationLogger.getLogMessageDetails("ldapmodify", true,
           NullOutputStream.getPrintStream());

      assertEquals(logDetails.getLogFiles().size(), 1);
      for (final File f : logDetails.getLogFiles())
      {
        assertTrue(f.getAbsolutePath().endsWith(
             "logs/tools/custom-name.log".replace('/', File.separatorChar)));
      }

      writeToPropertiesFile("ldapmodify.log-file-path=" +
           "logs/tools/ldapmodify-tool-invocation.log".replace('/',
                File.separatorChar));
      logDetails = ToolInvocationLogger.getLogMessageDetails(
           "ldapmodify", true, NullOutputStream.getPrintStream());

      assertEquals(logDetails.getLogFiles().size(), 2);

      // Test toString().
      assertTrue(logDetails.toString().contains(
           "/ldapmodify-tool-invocation.log".replace('/', File.separatorChar)));
      assertTrue(logDetails.toString().contains(
           "/custom-name.log".replace('/', File.separatorChar)));

      writeToPropertiesFile(
           "ldapmodify.include-in-default-log=false");
      logDetails = ToolInvocationLogger.getLogMessageDetails(
           "ldapmodify", true, NullOutputStream.getPrintStream());

      assertEquals(logDetails.getLogFiles().size(), 1);
      for (final File f : logDetails.getLogFiles())
      {
        assertFalse(f.getAbsolutePath().endsWith(
             "logs/tools/custom-name.log".replace('/', File.separatorChar)));
      }

      writeToPropertiesFile(
           "ldapmodify.include-in-default-log=true");
      logDetails = ToolInvocationLogger.getLogMessageDetails(
           "ldapmodify", true, NullOutputStream.getPrintStream());

      assertEquals(logDetails.getLogFiles().size(), 2);
    }
    catch (final Exception e)
    {
      throw e;
    }
    finally
    {
      deletePropertiesFile();
    }
  }



  /**
   * Tests if arguments are properly logged.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testArgumentsLog()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final ByteArrayInputStream in = getInputStream(
         "dn: ou=new,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: new");
    final File toolsPropertyFile = new File(configDir, "tools.properties");
    try
    {
      final PrintWriter toolsPropertiesWriter =
           new PrintWriter(new FileWriter(toolsPropertyFile, true));
      toolsPropertiesWriter.append("characterSet=UTF-8");
      toolsPropertiesWriter.close();
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      LDAPModify.main(in, out, out,
           "--hostname", "localhost",
           "--port", String.valueOf(ds.getListenPort()),
           "--bindDN", "cn=Directory Manager",
           "--retryFailedOperations",
           "--ratePerSecond", "1000",
           "--bindPassword", "password",
           "--propertiesFilePath",
           toolsPropertyFile.getAbsolutePath());

      final String log = readLog(new File(logsToolsDir, "tool-invocation.log"));
      assertTrue(log.contains(
           "# Arguments obtained from '" + toolsPropertyFile.toPath()));
      assertTrue(log.contains("--characterSet UTF-8"));
      assertTrue(log.contains("ldapmodify --hostname localhost"));
      assertTrue(log.contains("--bindDN \"cn=Directory Manager\""));
      assertTrue(log.contains("--retryFailedOperations"));
      assertTrue(log.contains("Exit Code: 0"));
      assertTrue(log.contains("Exit Message: success"));
    }
    finally
    {
      assertTrue(toolsPropertyFile.delete());
    }
  }



  /**
   * Tests logging invoked by possible JVM shutdown.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJVMShutdownLogging()
         throws Exception
  {
    final ToolInvocationLogDetails logDetails =
         ToolInvocationLogger.getLogMessageDetails("ldapmodify", true,
              NullOutputStream.getPrintStream());
    final ToolInvocationLogShutdownHook shutdownHook =
         new ToolInvocationLogShutdownHook(logDetails);
    shutdownHook.run();

    final String log = readLog(new File(logsToolsDir, "tool-invocation.log"));
    assertTrue(log.contains(INFO_TOOL_INTERRUPTED_BY_JVM_SHUTDOWN.get()), log);
  }



  /**
   * Tests the creation of log files upon tool invocation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLogFileCreation()
         throws Exception
  {
    try
    {
      final InMemoryDirectoryServer ds = getTestDS(true, true);

      writeToPropertiesFile("ldapsearch.log-tool-invocations=true");
      writeToPropertiesFile("ldapsearch.log-file-path=" +
           "logs/tools/ldapmodify-tool-invocation.log".replace('/',
                File.separatorChar));
      writeToPropertiesFile("default.log-file-path=" +
           logsToolsDir.getAbsolutePath()
           + "/custom-tool-invocation.log".replace('/', File.separatorChar));

      LDAPSearch.main(NullOutputStream.getPrintStream(),
           NullOutputStream.getPrintStream(),
           "--hostname", "localhost",
           "--port", String.valueOf(ds.getListenPort()),
           "--bindPassword", "password",
           "--baseDN", "dc=example,dc=com",
           "--bindDN", "cn=Directory Manager",
           "(sn=Yuan)",
           "givenName",
           "l",
           "st");

      final File defaultLog =
           new File(logsToolsDir, "custom-tool-invocation.log");
      final File specificLog =
           new File(logsToolsDir, "ldapmodify-tool-invocation.log");

      assertTrue(defaultLog.exists());
      assertTrue(specificLog.exists());

      final String defaultLogContents = readLog(defaultLog);
      final String specificLogContents = readLog(specificLog);

      assertTrue(defaultLogContents.equals(specificLogContents));
      // Ensure no arguments were received from any properties file.
      assertFalse(defaultLogContents.contains("# Arguments obtained from"));
      // Ensure trailing arguments are in the correct order.
      assertTrue(defaultLogContents.contains("\"(sn=Yuan)\" givenName l st"));
    }
    finally
    {
      deletePropertiesFile();
    }
  }



  /**
   * Tests the proper logging of subcommands.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubcommandLog()
         throws Exception
  {
    try
    {
      writeToPropertiesFile("base64.log-tool-invocations=true");

      final File outputFile = createTempFile();
      assertTrue(outputFile.delete());

      Base64Tool.main(
           "encode",
           "-d" ,"something",
           "-o", outputFile.getAbsolutePath());

      final File defaultLog = new File(logsToolsDir, "tool-invocation.log");
      assertTrue(defaultLog.exists());

      final String defaultLogContents = readLog(defaultLog);

      assertTrue(defaultLogContents.contains(
           "base64 encode --data something --outputFile "));
    }
    finally
    {
      deletePropertiesFile();
    }
  }



  /**
   * Tests if arguments are properly logged if all properties were taken from
   * properties file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testArgumentsLogOnlyFromPropertyFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final ByteArrayInputStream in = getInputStream(
         "dn: ou=new,dc=example,dc=com",
         "changeType: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: new");
    final File toolsPropertyFile = new File(configDir, "tools.properties");
    try
    {
      final PrintWriter fileWriter =
           new PrintWriter(new FileWriter(toolsPropertyFile, true));
      StringBuilder builder = new StringBuilder();
      builder.append("hostname=localhost");
      builder.append(StaticUtils.EOL);
      builder.append("port=");
      builder.append(ds.getListenPort());
      builder.append(StaticUtils.EOL);
      builder.append("bindDN=cn=Directory Manager");
      builder.append(StaticUtils.EOL);
      builder.append("ratePerSecond=1000");
      builder.append(StaticUtils.EOL);
      builder.append("bindPassword=password");
      builder.append(StaticUtils.EOL);
      builder.append("characterSet=UTF-8");
      builder.append(StaticUtils.EOL);
      fileWriter.append(builder.toString());
      fileWriter.close();

      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      LDAPModify.main(in, out, out,
           "--propertiesFilePath", toolsPropertyFile.getAbsolutePath());

      final String log = readLog(new File(logsToolsDir, "tool-invocation.log"));
      assertTrue(
           log.contains(
                "# Arguments obtained from '" + toolsPropertyFile.toPath()),
           log);
      assertTrue(log.contains("#      --hostname localhost"), log);
      assertTrue(log.contains("#      --bindDN \"cn=Directory Manager\""), log);
      assertTrue(log.contains("#      --characterSet UTF-8"), log);
      assertTrue(log.contains("#      --ratePerSecond 1000"), log);
    }
    finally
    {
      assertTrue(toolsPropertyFile.delete());
    }
  }



  /**
   * Tests a failsafe measure that tries to ensure that passwords get redacted
   * even if the associated argument is not marked sensitive.
   *
   * @param  argumentName  The name of the argument, without the dashes.
   * @param  shouldRedact  Indicates whether the value should be redacted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "PasswordRedactionFailsafeTestData")
  public void testPasswordRedactionFailsafe(final String argumentName,
                                            final boolean shouldRedact)
         throws Exception
  {
    final File logFile1 = createTempFile();
    final ToolInvocationLogDetails logDetails1 =
         ToolInvocationLogDetails.createLogDetails("test-command", null,
              Collections.singleton(logFile1), System.err);
    ToolInvocationLogger.logLaunchMessage(logDetails1,
         Collections.singletonList(
              new ObjectPair<>("--" + argumentName, "argumentValue")),
         Collections.<ObjectPair<String,String>>emptyList(), null);

    final String log1 = readLog(logFile1);
    if (shouldRedact)
    {
      assertTrue(
           log1.contains(
                "test-command --" + argumentName + " '*****REDACTED*****'"),
           log1);
    }
    else
    {
      assertTrue(
           log1.contains("test-command --" + argumentName + " argumentValue"),
           log1);
    }


    final File logFile2 = createTempFile();
    final ToolInvocationLogDetails logDetails2 =
         ToolInvocationLogDetails.createLogDetails("test-command", null,
              Collections.singleton(logFile2), System.err);
    ToolInvocationLogger.logLaunchMessage(logDetails2,
         Collections.singletonList(
              new ObjectPair<>("--" + argumentName, "*****REDACTED*****")),
         Collections.<ObjectPair<String,String>>emptyList(), null);

    final String log2 = readLog(logFile2);
    assertTrue(log2.contains(
         "test-command --" + argumentName + " '*****REDACTED*****'"),
         log2);


    final File logFile3 = createTempFile();
    final ToolInvocationLogDetails logDetails3 =
         ToolInvocationLogDetails.createLogDetails("test-command", null,
              Collections.singleton(logFile3), System.err);
    ToolInvocationLogger.logLaunchMessage(logDetails3,
         Collections.singletonList(
              new ObjectPair<>("--" + argumentName, "already-redacted")),
         Collections.<ObjectPair<String,String>>emptyList(), null);

    final String log3 = readLog(logFile3);
    assertTrue(log3.contains(
         "test-command --" + argumentName + " already-redacted"),
         log3);
  }



  /**
   * Retrieves a set of test data for use by the
   * {@link #testPasswordRedactionFailsafe} method.
   *
   * @return  A set of test data for use by the
   *          {@code testPasswordRedactionFailsafe} method.
   */
  @DataProvider(name = "PasswordRedactionFailsafeTestData")
  public Object[][] getPasswordRedactionFailsafeTestData()
  {
    return new Object[][]
    {
      new Object[]
      {
        "password",
        true
      },
      new Object[]
      {
        "Password",
        true
      },
      new Object[]
      {
        "PassWord",
        true
      },
      new Object[]
      {
        "PASSWORD",
        true
      },
      new Object[]
      {
        "password1",
        true
      },
      new Object[]
      {
        "password-1",
        true
      },
      new Object[]
      {
        "passwordfoo",
        true
      },
      new Object[]
      {
        "passwordFoo",
        true
      },
      new Object[]
      {
        "password-foo",
        true
      },
      new Object[]
      {
        "bindpassword",
        true
      },
      new Object[]
      {
        "bindPassword",
        true
      },
      new Object[]
      {
        "bind-password",
        true
      },
      new Object[]
      {
        "foopasswordbar",
        true
      },
      new Object[]
      {
        "fooPasswordBar",
        true
      },
      new Object[]
      {
        "foo-password-bar",
        true
      },
      new Object[]
      {
        "passphrase",
        true
      },
      new Object[]
      {
        "Passphrase",
        true
      },
      new Object[]
      {
        "PassPhrase",
        true
      },
      new Object[]
      {
        "PASSphrase",
        true
      },
      new Object[]
      {
        "passphrase1",
        true
      },
      new Object[]
      {
        "passphrase-1",
        true
      },
      new Object[]
      {
        "passphrasefoo",
        true
      },
      new Object[]
      {
        "passphraseFoo",
        true
      },
      new Object[]
      {
        "passphrase-foo",
        true
      },
      new Object[]
      {
        "bindpassphrase",
        true
      },
      new Object[]
      {
        "bindPassphrase",
        true
      },
      new Object[]
      {
        "bind-passphrase",
        true
      },
      new Object[]
      {
        "foopassphrasebar",
        true
      },
      new Object[]
      {
        "fooPassphraseBar",
        true
      },
      new Object[]
      {
        "foo-passphrase-bar",
        true
      },
      new Object[]
      {
        "pin",
        true
      },
      new Object[]
      {
        "Pin",
        true
      },
      new Object[]
      {
        "PIN",
        true
      },
      new Object[]
      {
        "encryption-pin",
        true
      },
      new Object[]
      {
        "encryptionPin",
        true
      },
      new Object[]
      {
        "encryptionPIN",
        true
      },
      new Object[]
      {
        "encryption-Pin",
        true
      },
      new Object[]
      {
        "encryption-PIN",
        true
      },
      new Object[]
      {
        "passwordfile",
        false
      },
      new Object[]
      {
        "passwordFile",
        false
      },
      new Object[]
      {
        "password-file",
        false
      },
      new Object[]
      {
        "PasswordFile",
        false
      },
      new Object[]
      {
        "Password-File",
        false
      },
      new Object[]
      {
        "PassWordFile",
        false
      },
      new Object[]
      {
        "PassWord-File",
        false
      },
      new Object[]
      {
        "PASSWORDFILE",
        false
      },
      new Object[]
      {
        "PASSWORD-FILE",
        false
      },
      new Object[]
      {
        "passwordpath",
        false
      },
      new Object[]
      {
        "passwordPath",
        false
      },
      new Object[]
      {
        "password-path",
        false
      },
      new Object[]
      {
        "PasswordPath",
        false
      },
      new Object[]
      {
        "Password-Path",
        false
      },
      new Object[]
      {
        "PassWordPath",
        false
      },
      new Object[]
      {
        "PassWord-Path",
        false
      },
      new Object[]
      {
        "PASSWORDPATH",
        false
      },
      new Object[]
      {
        "PASSWORD-PATH",
        false
      },
      new Object[]
      {
        "passphrasefile",
        false
      },
      new Object[]
      {
        "passphraseFile",
        false
      },
      new Object[]
      {
        "passphrase-file",
        false
      },
      new Object[]
      {
        "PassphraseFile",
        false
      },
      new Object[]
      {
        "Passphrase-File",
        false
      },
      new Object[]
      {
        "PassPhraseFile",
        false
      },
      new Object[]
      {
        "PassPhrase-File",
        false
      },
      new Object[]
      {
        "PASSPHRASEFILE",
        false
      },
      new Object[]
      {
        "PASSPHRASE-FILE",
        false
      },
      new Object[]
      {
        "passphrasepath",
        false
      },
      new Object[]
      {
        "passphrasePath",
        false
      },
      new Object[]
      {
        "passphrase-path",
        false
      },
      new Object[]
      {
        "PassphrasePath",
        false
      },
      new Object[]
      {
        "Passphrase-Path",
        false
      },
      new Object[]
      {
        "PassPhrasePath",
        false
      },
      new Object[]
      {
        "PassPhrase-Path",
        false
      },
      new Object[]
      {
        "PASSPHRASEPATH",
        false
      },
      new Object[]
      {
        "PASSPHRASE-PATH",
        false
      },
      new Object[]
      {
        "pinfile",
        false
      },
      new Object[]
      {
        "pinFile",
        false
      },
      new Object[]
      {
        "pin-File",
        false
      },
      new Object[]
      {
        "Pinfile",
        false
      },
      new Object[]
      {
        "PinFile",
        false
      },
      new Object[]
      {
        "Pin-File",
        false
      },
      new Object[]
      {
        "PINfile",
        false
      },
      new Object[]
      {
        "PINFile",
        false
      },
      new Object[]
      {
        "PIN-file",
        false
      },
      new Object[]
      {
        "PIN-FILE",
        false
      },
      new Object[]
      {
        "encryption-pin-file",
        false
      },
      new Object[]
      {
        "encryptionPinFile",
        false
      },
      new Object[]
      {
        "encryptionPINFile",
        false
      },
      new Object[]
      {
        "encryption-Pin-File",
        false
      },
      new Object[]
      {
        "encryption-PIN-file",
        false
      },
    };
  }



  /**
   * Helper method to write properties to property file. Will create property
   * file if it doesn't exist and will append to the current property file
   * should it exist.
   *
   * @param properties Properties to be written to properties file.
   *
   * @throws  IOException  If an unexpected problem occurs.
   */
  private void writeToPropertiesFile(final String... properties)
          throws IOException
  {
    final PrintWriter propertiesWriter = new PrintWriter(new FileWriter(
            new File(configDir, "tool-invocation-logging.properties"), true));
    for (final String property : properties)
    {
      propertiesWriter.append(property);
      propertiesWriter.append(StaticUtils.EOL);
    }
    propertiesWriter.close();
  }



  /**
   * Helper method to delete temporary properties file.
   */
  private void deletePropertiesFile()
  {
    final File f = new File(configDir, "tool-invocation-logging.properties");
    if (f.exists())
    {
      assertTrue(f.delete());
    }
  }



  /**
   * Helper method to read a log file.
   *
   * @param log The log file.
   *
   * @return A string representing the contents of the log file.
   *
   * @throws IOException If something goes wrong.
   */
  private static String readLog(final File log)
          throws IOException
  {
    final StringBuilder logBuilder = new StringBuilder();
    for (final String line :
         Files.readAllLines(log.toPath(), Charset.forName("UTF-8")))
    {
      logBuilder.append(line);
      logBuilder.append(StaticUtils.EOL);
    }
    return logBuilder.toString();
  }



  /**
   * Retrieves an input stream that may be used to read the provided lines.
   *
   * @param  lines  The lines to make available in the input stream.
   *
   * @return  An input stream that may be used to read the provided lines.
   */
  private static ByteArrayInputStream getInputStream(final String... lines)
  {
    if (lines.length == 0)
    {
      return new ByteArrayInputStream(StaticUtils.NO_BYTES);
    }

    final ByteStringBuffer buffer = new ByteStringBuffer();
    for (final String line : lines)
    {
      buffer.append(line);
      buffer.append(StaticUtils.EOL_BYTES);
    }

    return new ByteArrayInputStream(buffer.toByteArray());
  }
}
