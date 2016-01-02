/*
 * Copyright 2008-2016 UnboundID Corp.
 * All Rights Reserved.
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
 * checking for the Minimal Edition.  Checks that it performs include:
 * <UL>
 *   <LI>Make sure that the LICENSE.txt, LICENSE-GPLv2.txt,
 *       LICENSE-LGPLv2.1.txt, and LICENSE-UnboundID-LDAPSDK.txt files
 *       exist.</LI>
 *   <LI>Make sure that we can perform some basic LDAP operations using the
 *       Minimal Edition library (if a test directory is available).</LI>
 * </UL>
 */
public class SanityCheckME
       extends Task
{
  // The base directory for the Minimal Edition release.
  private File baseDir;

  // The string representation of the test server port, if available.
  private String dsPort;

  // The test server address, if available.
  private String dsHost;



  /**
   * Create a new instance of this task.
   */
  public SanityCheckME()
  {
    baseDir = null;
    dsHost  = null;
    dsPort  = null;
  }



  /**
   * Specifies the base directory for the Minimal Edition.
   *
   * @param  baseDir  The base directory for the Minimal Edition.
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


      // Make sure that the README.txt file exists and that it is for the
      // Minimal Edition.
      File readmeFile = new File(baseDir, "README.txt");
      if (! readmeFile.exists())
      {
        throw new BuildException("ERROR:  Could not find readme file " +
                                 readmeFile.getAbsolutePath());
      }

      ensureFileContains(readmeFile,
                         "UnboundID LDAP SDK for Java (Minimal Edition)");


      // Make sure that the docs/javadoc directory exists.
      File docsDir = new File(baseDir, "docs");
      File javadocDir = new File(docsDir, "javadoc");
      if (! javadocDir.exists())
      {
        throw new BuildException("ERROR:  Could not find javadoc directory " +
                                 javadocDir.getAbsolutePath());
      }


      // Make sure that a src.zip file exists.
      File srcZipFile = new File(baseDir, "src.zip");
      if (! srcZipFile.exists())
      {
        throw new BuildException("ERROR:  Could not find src.zip file " +
                                 srcZipFile.getAbsolutePath());
      }


      // Ensure that the unboundid-ldapsdk-me.jar file exists.
      File sdkJarFile = new File(baseDir, "unboundid-ldapsdk-me.jar");
      if (! sdkJarFile.exists())
      {
        throw new BuildException("ERROR:  Could not find SDK jar file:  " +
                                 sdkJarFile.getAbsolutePath());
      }


      // Finally, try to perform some LDAP operations to ensure that the SDK
      // appears to be functional.
      validateSDKIsUsable();
    }
    catch (BuildException be)
    {
      throw be;
    }
    catch (Exception e)
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
    catch (IOException ioe)
    {
      throw new BuildException("Unable to check whether file " +
                               f.getAbsolutePath() + " contains string '" + s +
                               "':  " + ioe, ioe);
    }
    finally
    {
      try
      {
        reader.close();
      } catch (Exception e) {}
    }
  }



  /**
   * Validates that the Minimal Edition of the SDK appears to be usable by at
   * least instantiating some key SDK data structures.  If a directory server
   * instance is available, then try to communicate with it.
   *
   * @throws  BuildException  If a problem occurs while trying to use the SDK.
   */
  private void validateSDKIsUsable()
          throws BuildException
  {
    // First, try to instantiate common SDK data structures.
    try
    {
      LDAPConnection connection = new LDAPConnection();

      Attribute attribute = new Attribute("name", "value");

      DN dn = new DN("dc=example,dc=com");

      Entry entry = new Entry(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      Filter filter = Filter.create("(objectClass=*)");

      Modification mod = new Modification(ModificationType.REPLACE, "foo",
                                          "bar");
    }
    catch (Exception e)
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
      } catch (Exception e) {}
    }

    if ((port > 0) && (port < 65536))
    {
      try
      {
        LDAPConnection conn = new LDAPConnection(address, port);
        RootDSE rootDSE = conn.getRootDSE();
        conn.close();
      }
      catch (LDAPException le)
      {
        throw new BuildException("ERROR:  Unable to retrieve root DSE from " +
             "directory server " + address + ':' + port + ":  " + le, le);
      }
    }
  }
}
