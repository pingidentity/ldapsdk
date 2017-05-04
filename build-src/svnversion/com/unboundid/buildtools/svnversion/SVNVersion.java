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
package com.unboundid.buildtools.svnversion;



import java.io.File;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.auth.ISVNAuthenticationManager;
import org.tmatesoft.svn.core.wc.SVNInfo;
import org.tmatesoft.svn.core.wc.SVNRevision;
import org.tmatesoft.svn.core.wc.SVNWCClient;



/**
 * This class provides an Ant task that can be used to determine the
 * revision number of the Subversion repository in which this source resides.
 */
public class SVNVersion
       extends Task
{
  // The base directory for the LDAP SDK source tree.
  private File baseDir;

  // The name of the property to set with the subversion path.
  private String pathPropertyName;

  // The name of the property to set with the subversion revision.
  private String revisionPropertyName;



  /**
   * Create a new instance of this task.
   */
  public SVNVersion()
  {
    baseDir              = null;
    pathPropertyName     = null;
    revisionPropertyName = null;
  }



  /**
   * Specifies the base directory for the LDAP SDK source tree.
   *
   * @param  baseDir  The base directory for the LDAP SDK source tree.
   */
  public void setBaseDir(final File baseDir)
  {
    this.baseDir = baseDir;
  }



  /**
   * Specifies the name of the property that should be set with the Subversion
   * path for the base directory.
   *
   * @param  pathPropertyName  The name of the property that should be set with
   *                           the Subversion path for the base directory.
   */
  public void setPathPropertyName(final String pathPropertyName)
  {
    this.pathPropertyName = pathPropertyName;
  }



  /**
   * Specifies the name of the property that should be set with the Subversion
   * revision number.
   *
   * @param  revisionPropertyName  The name of the property that should be set
   *                               with the Subversion revision number.
   */
  public void setRevisionPropertyName(final String revisionPropertyName)
  {
    this.revisionPropertyName = revisionPropertyName;
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
    // Make sure that the base directory was specified.
    if (baseDir == null)
    {
      throw new BuildException("ERROR:  No base directory specified.");
    }


    // Make sure that the property names were specified.
    if (pathPropertyName == null)
    {
      throw new BuildException("ERROR:  No path property name specified.");
    }

    if (revisionPropertyName == null)
    {
      throw new BuildException("ERROR:  No revision property name specified.");
    }


    try
    {
      // Create the Subversion client and use it to invoke the equivalent of
      // "svn info".
      final SVNWCClient svn =
           new SVNWCClient((ISVNAuthenticationManager) null, null);
      final SVNInfo svnInfo = svn.doInfo(baseDir, SVNRevision.WORKING);
      getProject().setProperty(revisionPropertyName,
           String.valueOf(svnInfo.getRevision().getNumber()));
      getProject().setProperty(pathPropertyName,
           String.valueOf(svnInfo.getURL().getPath()));
    }
    catch (final  SVNException svne)
    {
      // This could happen if the Subversion repository version is incompatible
      // with the subversion client library, or if we have a workspace that
      // isn't a Subversion checkout.  We don't want to make the build fail in
      // this case, but we will want to print an error message.
      getProject().setProperty(revisionPropertyName, "-1");

      String projectBasePath;
      try
      {
        projectBasePath = baseDir.getCanonicalPath();
      }
      catch (final Exception e)
      {
        projectBasePath = baseDir.getAbsolutePath();
      }

      getProject().setProperty(pathPropertyName,
           projectBasePath.replace("\\", "\\\\"));

      System.err.println("ERROR:  Unable to determine the subversion " +
           "revision number and/or path:  " + String.valueOf(svne) +
           ".  Using a default revision number of -1 and a path that is the " +
           "workspace base path of " + projectBasePath);
    }
    catch (final Exception e)
    {
      getProject().setProperty(revisionPropertyName, "-1");
      getProject().setProperty(pathPropertyName, baseDir.getAbsolutePath());
      throw new BuildException(e);
    }
  }
}
