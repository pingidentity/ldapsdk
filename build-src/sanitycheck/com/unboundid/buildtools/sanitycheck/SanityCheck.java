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
package com.unboundid.buildtools.sanitycheck;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.StringTokenizer;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.util.InternalUseOnly;

import static com.unboundid.ldap.sdk.Version.*;



/**
 * This class provides an Ant task that can be used to perform basic sanity
 * checking for the LDAP SDK.  Checks that it performs include:
 * <UL>
 *   <LI>Make sure that all of the expected files are present in the build.</LI>
 *   <LI>Make sure that all source files include the GPLv2 and LGPLv2.1
 *       headers.</LI>
 *   <LI>Make sure that the LICENSE.txt, LICENSE-GPLv2.txt,
 *       LICENSE-LGPLv2.1.txt, and LICENSE-UnboundID-LDAPSDK.txt files
 *       exist.</LI>
 *   <LI>Make sure that we can perform some basic LDAP operations using the
 *       resulting library (if a test directory is available).</LI>
 * </UL>
 */
public class SanityCheck
       extends Task
{
  /**
   * An explicit list of the packages that are allowed to be included in the
   * LDAP SDK.  Any content found in the jar file that is associated with any
   * other package will generate an error.  Note that sub-packages are NOT
   * automatically included.
   */
  public static final String[] PACKAGES =
  {
    "com.unboundid.asn1",
    "com.unboundid.ldap.listener",
    "com.unboundid.ldap.listener.interceptor",
    "com.unboundid.ldap.matchingrules",
    "com.unboundid.ldap.protocol",
    "com.unboundid.ldap.sdk",
    "com.unboundid.ldap.sdk.controls",
    "com.unboundid.ldap.sdk.examples",
    "com.unboundid.ldap.sdk.experimental",
    "com.unboundid.ldap.sdk.extensions",
    "com.unboundid.ldap.sdk.migrate.jndi",
    "com.unboundid.ldap.sdk.migrate.ldapjdk",
    "com.unboundid.ldap.sdk.persist",
    "com.unboundid.ldap.sdk.schema",
    "com.unboundid.ldap.sdk.transformations",
    "com.unboundid.ldap.sdk.unboundidds",
    "com.unboundid.ldap.sdk.unboundidds.controls",
    "com.unboundid.ldap.sdk.unboundidds.examples",
    "com.unboundid.ldap.sdk.unboundidds.extensions",
    "com.unboundid.ldap.sdk.unboundidds.jsonfilter",
    "com.unboundid.ldap.sdk.unboundidds.logs",
    "com.unboundid.ldap.sdk.unboundidds.monitors",
    "com.unboundid.ldap.sdk.unboundidds.tasks",
    "com.unboundid.ldap.sdk.unboundidds.tools",
    "com.unboundid.ldif",
    "com.unboundid.util",
    "com.unboundid.util.args",
    "com.unboundid.util.json",
    "com.unboundid.util.parallel",
    "com.unboundid.util.ssl",
    "com.unboundid.util.ssl.cert"
  };



  // The base directory for the release.
  private File baseDir;

  // The set of packages imported for OSGi.
  private final HashSet<String> osgiImportedPackages;

  // The set of packages imported from the source.
  private final HashSet<String> srcImportedPackages;

  // The string representation of the test server port, if available.
  private String dsPort;

  // The test server address, if available.
  private String dsHost;



  /**
   * Create a new instance of this task.
   */
  public SanityCheck()
  {
    baseDir              = null;
    osgiImportedPackages = new HashSet<>(50);
    srcImportedPackages  = new HashSet<>(50);
  }



  /**
   * Specifies the base directory for the release.
   *
   * @param  baseDir  The base directory for the release.
   */
  public void setBaseDir(final File baseDir)
  {
    this.baseDir = baseDir;
  }



  /**
   * Specifies the address of a directory server instance that can be used to
   * test basic LDAP communication.
   *
   * @param  dsHost  The address of a directory server instance that can be used
   *                 to test basic LDAP communication.
   */
  public void setDsHost(final String dsHost)
  {
    this.dsHost = dsHost;
  }



  /**
   * Specifies the string representation of the port for a directory server
   * instance that can be used to test basic LDAP communication.
   *
   * @param  dsPort  The string representation of the port for a directory
   *                 server instance that can be used to test basic LDAP
   *                 communication.
   */
  public void setDsPort(final String dsPort)
  {
    this.dsPort = dsPort;
  }



  /**
   * Performs all necessary processing for this task.
   *
   * @throws  BuildException  If a problem is encountered.
   */
  @Override()
  public void execute()
         throws BuildException
  {
    try
    {
      // Make sure that the base directory was specified.
      if (baseDir == null)
      {
        throw new BuildException("ERROR:  No base directory specified.");
      }


      // Make sure that the appropriate license files exist.
      File licenseFile = new File(baseDir, "LICENSE.txt");
      if (! licenseFile.exists())
      {
        throw new BuildException("ERROR:  Could not find license file " +
                                 licenseFile.getAbsolutePath());
      }

      licenseFile = new File(baseDir, "LICENSE-GPLv2.txt");
      if (! licenseFile.exists())
      {
        throw new BuildException("ERROR:  Could not find license file " +
                                 licenseFile.getAbsolutePath());
      }

      licenseFile = new File(baseDir, "LICENSE-LGPLv2.1.txt");
      if (! licenseFile.exists())
      {
        throw new BuildException("ERROR:  Could not find license file " +
                                 licenseFile.getAbsolutePath());
      }

      licenseFile = new File(baseDir, "LICENSE-UnboundID-LDAPSDK.txt");
      if (! licenseFile.exists())
      {
        throw new BuildException("ERROR:  Could not find license file " +
                                 licenseFile.getAbsolutePath());
      }


      // Make sure that the README.txt file exists.
      final File readmeFile = new File(baseDir, "README.txt");
      if (! readmeFile.exists())
      {
        throw new BuildException("ERROR:  Could not find readme file " +
                                 readmeFile.getAbsolutePath());
      }

      ensureFileContains(readmeFile, "UnboundID LDAP SDK for Java");


      // Make sure that the docs/javadoc directory exists and that it only
      // contains the appropriate content.
      final File docsDir = new File(baseDir, "docs");
      final File javadocDir = new File(docsDir, "javadoc");
      if (! javadocDir.exists())
      {
        throw new BuildException("ERROR:  Could not find javadoc directory " +
                                 javadocDir.getAbsolutePath());
      }

      validateJavadocDir(javadocDir);


      // Make sure that the examples directory exists and that all files
      // contained it it have the Apache and GPLv2/LGPLv2.1license headers.
      final File examplesDir = new File(docsDir, "examples");
      if (! examplesDir.exists())
      {
        throw new BuildException("ERROR:  Could not find examples directory " +
                                 examplesDir.getAbsolutePath());
      }

      for (final File f : examplesDir.listFiles())
      {
        if (f.getName().endsWith(".java"))
        {
          ensureFileContains(f, "Apache License, Version 2.0");
          ensureFileContains(f, "GNU General Public License (GPLv2 only)");
          ensureFileContains(f,
               "GNU Lesser General Public License (LGPLv2.1 only)");
        }
      }


      // Make sure that a src.zip file exists, that it only contains files that
      // are supposed to be part of the release, and that all of those files
      // contain the Apache and GPLv2/LGPLv2.1 license headers.
      final File srcZipFile = new File(baseDir, "src.zip");
      if (! srcZipFile.exists())
      {
        throw new BuildException("ERROR:  Could not find src.zip file " +
             srcZipFile.getAbsolutePath());
      }

      validateSrcZipFile(srcZipFile);


      // Ensure that the unboundid-ldapsdk.jar file exists and that
      // it only contains files which are supposed to be part of the release.
      final File sdkJarFile = new File(baseDir, "unboundid-ldapsdk.jar");
      if (! sdkJarFile.exists())
      {
        throw new BuildException("ERROR:  Could not find SDK jar file:  " +
                                 sdkJarFile.getAbsolutePath());
      }

      validateSDKJarFile(sdkJarFile);


      // Ensure that the manifest includes an appropriate set of OSGi imports.
      validateOSGiImports();


      // Finally, try to perform some LDAP operations to ensure that the SDK
      // appears to be functional.
      validateSDKIsUsable();
    }
    catch (final BuildException be)
    {
      throw be;
    }
    catch (final Exception e)
    {
      e.printStackTrace();
      throw new BuildException("Uncaught exception:  " + e, e);
    }
  }



  /**
   * Ensure that the specified file contains the given string.
   *
   * @param  f  The file to check.
   * @param  s  The string that must be present in the file.
   *
   * @throws  BuildException  If the specified file does not contain the
   *                          expected string.
   */
  private static void ensureFileContains(final File f, final String s)
          throws BuildException
  {
    BufferedReader reader = null;
    try
    {
      reader = new BufferedReader(new FileReader(f));

      String line = reader.readLine();
      while (line != null)
      {
        if (line.contains(s))
        {
          return;
        }

        line = reader.readLine();
      }

      // If we've gotten here, then we didn't find what we were looking for.
      throw new BuildException("File " + f.getAbsolutePath() +
                               " did not include expected string '" + s + '\'');
    }
    catch (final IOException ioe)
    {
      throw new BuildException("Unable to check whether file " +
                               f.getAbsolutePath() + " contains string '" + s +
                               "':  " + ioe, ioe);
    }
    finally
    {
      try
      {
        if (reader != null)
        {
          reader.close();
        }
      } catch (final Exception e) {}
    }
  }



  /**
   * Validate that the generated javadoc documentation only contains the
   * correct content.
   *
   * @param  javadocDir  The path to the base directory for javadoc files.
   *
   * @throws  BuildException  If a problem is encountered while examining the
   *                          javadoc.
   */
  private static void validateJavadocDir(final File javadocDir)
          throws BuildException
  {
    // Look at all of the directories below the javadocDir and ensure that they
    // only contain files that relate to the expected packages.  The only
    // exception to this should be the top-level resources directory.
    for (final File f : javadocDir.listFiles())
    {
      if (f.isDirectory())
      {
        if (f.getName().equals("resources") || f.getName().equals("jquery"))
        {
          continue;
        }

        examineJavadocPackage(f, f.getName());
      }
    }
  }



  /**
   * Recursively process the specified directory, ensuring that no regular files
   * are contained in any directory that is not associated with an expected
   * package.
   *
   * @param  packageDir   The path to the directory to examine.
   * @param  packageName  The name of the Java package associated with the
   *                      package directory.
   *
   * @throws  BuildException  If a problem is found with the content contained
   *                          in the specified directory.
   */
  private static void examineJavadocPackage(final File packageDir,
                                            final String packageName)
          throws BuildException
  {
    boolean isSEPackage = false;
    for (final String pkg : PACKAGES)
    {
      if (packageName.equals(pkg))
      {
        isSEPackage = true;
        break;
      }
    }

    for (final File f : packageDir.listFiles())
    {
      if (f.getAbsolutePath().contains("javadoc" + File.separator + "src-html" +
                                       File.separator))
      {
        continue;
      }

      if (f.isDirectory())
      {
        examineJavadocPackage(f, packageName + '.' + f.getName());
      }
      else
      {
        if (! isSEPackage)
        {
          throw new BuildException("Unexpected Javadoc file " +
               f.getAbsolutePath() + " found in package " + packageName +
               " which is not one of the expected packages.");
        }
      }
    }
  }



  /**
   * Validates the contents of the src.zip file to ensure that it doesn't
   * contain anything that isn't supposed to be there, that all of the files
   * that it does contain the Apache and GPLv2/LGPLv2.1 license headers, and
   * that none of those files import any content from an UnboundID package that
   * isn't contained in an expected package.
   *
   * @param  srcZipFile  The src.zip file to be examined.
   *
   * @throws  BuildException  If a problem is found with the content of the
   *                          src.zip file.
   */
  private void validateSrcZipFile(final File srcZipFile)
          throws BuildException
  {
    ZipFile zipFile = null;
    try
    {
      zipFile = new ZipFile(srcZipFile);

      final Enumeration<? extends ZipEntry> entries = zipFile.entries();
      while (entries.hasMoreElements())
      {
        final ZipEntry zipEntry = entries.nextElement();
        if (! zipEntry.isDirectory())
        {
          final String name = zipEntry.getName().replace('\\', '/');
          final int lastSlashPos = name.lastIndexOf('/');
          if (lastSlashPos > 0)
          {
            final String packageName =
                 name.substring(0, lastSlashPos).replace('/', '.');
            boolean acceptablePackage = false;
            for (final String pkg : PACKAGES)
            {
              if (packageName.equals(pkg))
              {
                acceptablePackage = true;
                break;
              }
            }

            if (! acceptablePackage)
            {
              throw new BuildException("ERROR:  Unexpected src.zip file " +
                   zipEntry.getName() + " found in package " + packageName +
                   " which is not one of the defined packages.");
            }

            final BufferedReader reader = new BufferedReader(
                 new InputStreamReader(zipFile.getInputStream(zipEntry)));
            try
            {
              boolean apacheHeaderFound = false;
              boolean gplHeaderFound = false;
              boolean lgplHeaderFound = false;
              String line = reader.readLine();
              while (line != null)
              {
                if (line.contains("Apache License, Version 2.0"))
                {
                  apacheHeaderFound = true;
                }
                else if (line.contains(
                     "GNU General Public License (GPLv2 only)"))
                {
                  gplHeaderFound = true;
                }
                else if (line.contains("GNU Lesser General Public License " +
                              "(LGPLv2.1 only)"))
                {
                  lgplHeaderFound = true;
                }
                else if (line.startsWith("import "))
                {
                  validateImportLine(zipEntry.getName(), line);
                }

                line = reader.readLine();
              }

              if (! apacheHeaderFound)
              {
                throw new BuildException("ERROR:  src.zip file " +
                     zipEntry.getName() + " is missing Apache License header.");
              }

              if (! gplHeaderFound)
              {
                throw new BuildException("ERROR:  src.zip file " +
                     zipEntry.getName() + " is missing GPLv2 header.");
              }

              if (! lgplHeaderFound)
              {
                throw new BuildException("ERROR:  src.zip file " +
                     zipEntry.getName() + " is missing LGPLv2.1 header.");
              }
            }
            finally
            {
              reader.close();
            }
          }
        }
      }
    }
    catch (final IOException ioe)
    {
      throw new BuildException("ERROR:  I/O error encountered while reading " +
           "src.zip file " + srcZipFile.getAbsolutePath() + ":  " + ioe);
    }
    finally
    {
      try
      {
        if (zipFile != null)
        {
          zipFile.close();
        }
      } catch (final Exception e) {}
    }
  }



  /**
   * Validates the contents of an import line to ensure that what is being
   * imported isn't from an UnboundID package that isn't one of the defined
   * packages.
   *
   * @param  fileName  The name of the file containing the source line.
   * @param  line      The line to be validated.
   *
   * @throws  BuildException  If the import line attempts to import UnboundID
   *                          content that isn't part of the release.
   */
  private void validateImportLine(final String fileName, final String line)
          throws BuildException
  {
    // First, make sure that we have the complete import line.  It could be that
    // this is a long line that got wrapped, and in that case we'll just assume
    // that it's acceptable.
    final int semicolonPos = line.indexOf(';');
    if (semicolonPos < 0)
    {
      return;
    }

    final StringTokenizer tokenizer = new StringTokenizer(line, " \t");

    String token = tokenizer.nextToken(); // This is the word "import".
    token = tokenizer.nextToken();

    if (token.equals("static"))
    {
      token = tokenizer.nextToken();

      // See if it's a star import.  If so, then strip off the
      // ".className.*;".  Otherwise, just strip off the ".className;".
      if (token.endsWith(".*;"))
      {
        token = token.substring(0, token.indexOf(".*;"));
      }

      final int lastDotPos = token.lastIndexOf('.');
      if (lastDotPos < 0)
      {
        throw new BuildException("ERROR:  Unexpected token " + token +
             " encountered on import line " + line + " of source file " +
             fileName);
      }
      token = token.substring(0, lastDotPos);
    }
    else
    {
      // See if it's a star import.  If so, then strip off the ".*;".
      // Otherwise, strip off the ".className;".
      if (token.endsWith(".*;"))
      {
        token = token.substring(0, token.indexOf(".*;"));
      }
      else
      {
        final int lastDotPos = token.lastIndexOf('.');
        if (lastDotPos < 0)
        {
          throw new BuildException("ERROR:  Unexpected token " + token +
               " encountered on import line " + line + " of source file " +
               fileName);
        }
        token = token.substring(0, lastDotPos);
      }
    }

    // If package name starts with "com.unboundid.", then it must be one of the
    // defined packages.
    if (token.startsWith("com.unboundid."))
    {
      boolean found = false;
      for (final String pkg : PACKAGES)
      {
        if (token.equals(pkg))
        {
          found = true;
          break;
        }
      }

      if (! found)
      {
        throw new BuildException("ERROR:  Source file " + fileName +
             " imports from package " + token + " which is not one of the " +
             "expected packages.");
      }
    }
    else if (! token.startsWith("java."))
    {
      srcImportedPackages.add(token);
    }
  }



  /**
   * Validates the contents of the unboundid-ldapsdk.jar file to
   * ensure that it doesn't contain anything that isn't supposed to be there.
   *
   * @param  jarFile  The unboundid-ldapsdk.jar file to be examined.
   *
   * @throws  BuildException  If a problem is found with the content of the jar
   *                          file.
   */
  private void validateSDKJarFile(final File jarFile)
          throws BuildException
  {
    JarFile jar = null;
    try
    {
      jar = new JarFile(jarFile);

      final HashSet<String> packageNames = new HashSet<>(50);

      // Look at the files contained in the jar to make sure they are correct.
      final Enumeration<? extends JarEntry> entries = jar.entries();
      while (entries.hasMoreElements())
      {
        final JarEntry jarEntry = entries.nextElement();
        if ((! jarEntry.isDirectory()) &&
            (! jarEntry.getName().startsWith("META-INF")))
        {
          final String name = jarEntry.getName().replace('\\', '/');
          final int lastSlashPos = name.lastIndexOf('/');
          if (lastSlashPos > 0)
          {
            // Try to load the class.  If we can't do it, then it shouldn't be
            // considered an error, but we want to be able to load at least one
            // class from each package so that the class loader knows about all
            // of the packages so we can see what annotations might be defined
            // for them.
            final int classPos = name.lastIndexOf(".class");
            if (classPos >  0)
            {
              final String className =
                   name.substring(0, classPos).replace('/', '.');
              try
              {
                Class.forName(className);
              } catch (final Exception e) {}
            }

            final String packageName =
                 name.substring(0, lastSlashPos).replace('/', '.');
            boolean acceptablePackage = false;
            for (final String pkg : PACKAGES)
            {
              if (packageName.equals(pkg))
              {
                acceptablePackage = true;
                break;
              }
            }

            if (! acceptablePackage)
            {
              throw new BuildException("ERROR:  Unexpected class file " +
                   jarEntry.getName() + " found in package " + packageName +
                   " of the " + jarFile.getAbsolutePath() + " jar file -- " +
                   "this class is not in any of the defined packages.");
            }

            packageNames.add(packageName);
          }
        }
      }

      // Look at the manifest to ensure that the list of exported packages is
      // correct.
      final Manifest manifest = jar.getManifest();
      if (manifest == null)
      {
        throw new BuildException("Unable to read the manifest from jar file " +
             jarFile.getAbsolutePath());
      }

      final Attributes attributes = manifest.getMainAttributes();
      if (attributes == null)
      {
        throw new BuildException("Could not find any main attributes in the " +
             jarFile.getAbsolutePath() + " manifest");
      }

      final String exportPackageStr = attributes.getValue("Export-Package");
      if (exportPackageStr == null)
      {
        throw new BuildException("Could not find an Export-Package attribute " +
             "in the " + jarFile.getAbsolutePath() + " manifest");
      }

      final String versionStr = ";version=\"" + MAJOR_VERSION + '.' +
           MINOR_VERSION + '.' + POINT_VERSION + '"';

      StringTokenizer tokenizer = new StringTokenizer(exportPackageStr, ", ");
      while (tokenizer.hasMoreTokens())
      {
        final String exportToken = tokenizer.nextToken();
        if (! exportToken.endsWith(versionStr))
        {
          throw new BuildException("Export-Package value " + exportToken +
               " does not end with expected version component " + versionStr);
        }

        final String packageName =
             exportToken.substring(0, exportToken.length()-versionStr.length());
        if (! packageNames.remove(packageName))
        {
          throw new BuildException("Unexpected package " + packageName +
               " found in the Export-Package attribute of the " +
               jarFile.getAbsolutePath() + " manifest");
        }
      }

      final String importPackageStr = attributes.getValue("Import-Package");
      if (importPackageStr == null)
      {
        throw new BuildException("Could not find an Import-Package attribute " +
             "in the " + jarFile.getAbsolutePath() + " manifest");
      }

      tokenizer = new StringTokenizer(importPackageStr, ", ");
      while (tokenizer.hasMoreTokens())
      {
        final String importToken = tokenizer.nextToken();
        if (osgiImportedPackages.contains(importToken))
        {
          throw new BuildException("Duplicate Import-Package value " +
               importToken + " found in the" + jarFile.getAbsolutePath() +
               " manifest");
        }
        else
        {
          osgiImportedPackages.add(importToken);
        }
      }

      // The only package names left in the set should be either the examples
      // package or be marked with an @InternalUseOnly annotation.
      for (final String packageName : packageNames)
      {
        if (packageName.endsWith(".examples"))
        {
          continue;
        }

        final Package p = Package.getPackage(packageName);
        if (p == null)
        {
          throw new BuildException("Unable to find any information about " +
               "package " + packageName + " contained in the " +
               jarFile.getAbsolutePath() + " jar file but not included in " +
               "the Export-Package manifest attribute");
        }

        if (! p.isAnnotationPresent(InternalUseOnly.class))
        {
          throw new BuildException("Package " + packageName + " contained in " +
               "jar file " + jarFile.getAbsolutePath() + " is not included " +
               "in the Export-Package manifest attribute and is not marked " +
               "@InternalUseOnly");
        }
      }
    }
    catch (final IOException ioe)
    {
      throw new BuildException("ERROR:  I/O error encountered while reading " +
                               "jar file " + jarFile.getAbsolutePath() +
                               ":  " + ioe, ioe);
    }
    finally
    {
      try
      {
        if (jar != null)
        {
          jar.close();
        }
      } catch (final Exception e) {}
    }
  }



  /**
   * Ensures that the jar file manifest contains an appropriate set of OSGi
   * imports based on the source imports.
   *
   * @throws  BuildException  If a problem is found with the imports.
   */
  private void validateOSGiImports()
          throws BuildException
  {
    for (final String s : srcImportedPackages)
    {
      if (! osgiImportedPackages.remove(s))
      {
        throw new BuildException("OSGi Import-Package manifest entry missing " +
            "source-imported package " + s);
      }
    }

    if (! osgiImportedPackages.isEmpty())
    {
      throw new BuildException("OSGi Import-Package values found for " +
           "packages not used in the source:  " + osgiImportedPackages);
    }
  }



  /**
   * Validates that the SDK appears to be usable by at least instantiating some
   * key SDK data structures.  If a directory server instance is available, then
   * try to communicate with it.
   *
   * @throws  BuildException  If a problem occurs while trying to use the SDK.
   */
  private void validateSDKIsUsable()
          throws BuildException
  {
    // First, try to instantiate common SDK data structures.
    try
    {
      final LDAPConnection connection = new LDAPConnection();

      final Attribute attribute = new Attribute("name", "value");

      final DN dn = new DN("dc=example,dc=com");

      final Entry entry = new Entry(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      final Filter filter = Filter.create("(objectClass=*)");

      final Modification mod =
           new Modification(ModificationType.REPLACE, "foo", "bar");
    }
    catch (final Exception e)
    {
      throw new BuildException("ERROR:  Unable to instantiate common SDK " +
                               "data structures:  " + e, e);
    }


    // If it appears that a directory server instance is available, then verify
    // that we can communicate with it.
    String address = dsHost;
    if ((address == null) || (address.length() == 0) ||
        (address.equals("${ds.host}")))
    {
      address = "127.0.0.1";
    }

    int port = -1;
    if (dsPort != null)
    {
      try
      {
        port = Integer.parseInt(dsPort);
      } catch (final Exception e) {}
    }

    if ((port > 0) && (port < 65536))
    {
      try
      {
        final LDAPConnection conn = new LDAPConnection(address, port);
        final RootDSE rootDSE = conn.getRootDSE();
        conn.close();
      }
      catch (final LDAPException le)
      {
        throw new BuildException("ERROR:  Unable to retrieve root DSE from " +
             "directory server " + address + ':' + port + ":  " + le, le);
      }
    }
  }
}
