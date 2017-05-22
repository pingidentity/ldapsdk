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
package com.unboundid.buildtools.repositoryinfo;



import java.io.File;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;

import org.tmatesoft.svn.core.auth.ISVNAuthenticationManager;
import org.tmatesoft.svn.core.wc.SVNInfo;
import org.tmatesoft.svn.core.wc.SVNRevision;
import org.tmatesoft.svn.core.wc.SVNWCClient;



/**
 * This class provides an Ant task that can be used to obtain information about
 * the subversion or git repository from which the LDAP SDK source was
 * retrieved.  For Subversion repositories, it uses the SVNKit library.  For git
 * repositories, it uses the JGit library.  If the source repository is neither
 * git or subversion, if the repository type cannot be determined, or if an
 * error occurs while interacting with the repository, then a default set of
 * values will be used.
 */
public class RepositoryInfo
       extends Task
{
  // The base directory for the workspace with the LDAP SDK source tree.
  private File baseDir;

  // The name of the property to set with the repository path.
  private String repositoryPathPropertyName;

  // The name of the property to set with the repository revision number.
  private String repositoryRevisionNumberPropertyName;

  // The name of the property to set with the repository revision.
  private String repositoryRevisionPropertyName;

  // The name of the property to set with the type of repository.
  private String repositoryTypePropertyName;

  // The name of the property to set with the repository URL.
  private String repositoryURLPropertyName;



  /**
   * Create a new instance of this task.
   */
  public RepositoryInfo()
  {
    baseDir                              = null;
    repositoryPathPropertyName           = null;
    repositoryRevisionNumberPropertyName = null;
    repositoryRevisionPropertyName       = null;
    repositoryTypePropertyName           = null;
    repositoryURLPropertyName            = null;
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
   * Specifies the name of the property that should be set with the path in the
   * repository from which the LDAP SDK source was obtained.
   *
   * @param  repositoryPathPropertyName  The name of the property that should be
   *                                     set with the path in the repository
   *                                     from which the LDAP SDK source was
   *                                     obtained.
   */
  public void setRepositoryPathPropertyName(
                   final String repositoryPathPropertyName)
  {
    this.repositoryPathPropertyName = repositoryPathPropertyName;
  }



  /**
   * Specifies the name of the property that should be set with the repository
   * revision from which the LDAP SDK source was obtained.
   *
   * @param  repositoryRevisionPropertyName  The name of the property that
   *                                         should be set with the repository
   *                                         revision from which the LDAP SDK
   *                                         source was obtained.
   */
  public void setRepositoryRevisionPropertyName(
                   final String repositoryRevisionPropertyName)
  {
    this.repositoryRevisionPropertyName = repositoryRevisionPropertyName;
  }



  /**
   * Specifies the name of the property that should be set with the numeric
   * revision number for the repository from which the LDAP SDK source was
   * obtained.
   *
   * @param  repositoryRevisionNumberPropertyName  The name of the property that
   *                                               should be set with the
   *                                               numeric revision number for
   *                                               the repository from which the
   *                                               LDAP SDK source was obtained.
   */
  public void setRepositoryRevisionNumberPropertyName(
                   final String repositoryRevisionNumberPropertyName)
  {
    this.repositoryRevisionNumberPropertyName =
         repositoryRevisionNumberPropertyName;
  }



  /**
   * Specifies the name of the property that should be set with the type of
   * repository from which the LDAP SDK source was obtained.
   *
   * @param  repositoryTypePropertyName  The name of the property that should be
   *                                     set with the type of repository from
   *                                     which the LDAP SDK source was obtained.
   */
  public void setRepositoryTypePropertyName(
                   final String repositoryTypePropertyName)
  {
    this.repositoryTypePropertyName = repositoryTypePropertyName;
  }



  /**
   * Specifies the name of the property that should be set with the URL to the
   * repository from which the LDAP SDK source was obtained.
   *
   * @param  repositoryURLPropertyName  The name of the property that should be
   *                                    set with the URL to the repository from
   *                                    which the LDAP SDK source was obtained.
   */
  public void setRepositoryURLPropertyName(
                   final String repositoryURLPropertyName)
  {
    this.repositoryURLPropertyName = repositoryURLPropertyName;
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
    // Make sure that the base directory was specified and that it exists.
    if (baseDir == null)
    {
      throw new BuildException("ERROR:  No base directory specified.");
    }

    if (! baseDir.exists())
    {
      throw new BuildException("ERROR:  Base directory " +
           baseDir.getAbsolutePath() + " does not exist.");
    }


    if (repositoryPathPropertyName == null)
    {
      throw new BuildException("ERROR:  The repositoryPathPropertyName " +
           "property was not set.");
    }

    if (repositoryRevisionPropertyName == null)
    {
      throw new BuildException("ERROR:  The repositoryRevisionPropertyName " +
           "property was not set.");
    }

    if (repositoryTypePropertyName == null)
    {
      throw new BuildException("ERROR:  The repositoryTypePropertyName " +
           "property was not set.");
    }

    if (repositoryURLPropertyName == null)
    {
      throw new BuildException("ERROR:  The repositoryURLPropertyName " +
           "property was not set.");
    }


    // Start in the base directory and work our way up the filesystem until
    // we find a ".git" or ".svn" directory.  If we find a ".git" directory,
    // then use the JGit library to get the repository path and revision.  If
    // we find a ".svn" directory, then use the SVNKit library.  If we can't
    // find either, then just use generic values.
    File f = baseDir;
    while ((f != null) && f.exists())
    {
      if (new File(f, ".git").exists())
      {
        try
        {
          getGitInfo();
          return;
        }
        catch (final Exception e)
        {
          System.err.println("ERROR:  Unable to obtain repository details " +
               "from the git workspace in directory " + f.getAbsolutePath() +
               ":  " + String.valueOf(e) +
               ".  Using fallback repository info.");
        }
      }

      if (new File(f, ".svn").exists())
      {
        try
        {
          getSubversionInfo();
          return;
        }
        catch (final Exception e)
        {
          System.err.println("ERROR:  Unable to obtain repository details " +
               "from the subversion workspace in directory " +
               f.getAbsolutePath() + ":  " + String.valueOf(e) +
               ".  Using fallback repository info.");
        }
      }

      f = f.getParentFile();
    }


    // If we've gotten here, then it doesn't look like we have either a git or a
    // subversion workspace.  Just use generic values for all of the properties.
    getProject().setProperty(repositoryTypePropertyName, "{unknown}");
    getProject().setProperty(repositoryURLPropertyName,
         "file://" + baseDir.getAbsolutePath());
    getProject().setProperty(repositoryPathPropertyName, "/");
    getProject().setProperty(repositoryRevisionPropertyName, "{unknown}");
    getProject().setProperty(repositoryRevisionNumberPropertyName, "-1");
  }



  /**
   * Obtains information about the git repository from which the LDAP SDK source
   * was obtained.
   *
   * @throws  Exception  If a problem is encountered while attempting to obtain
   *                     information about the git repository.
   */
  private void getGitInfo()
          throws Exception
  {
    final Repository r = new FileRepositoryBuilder().readEnvironment().
         findGitDir(baseDir).build();

    final String repoURL = r.getConfig().getString("remote", "origin", "url");
    final String repoRevision = r.resolve("HEAD").getName();

    final String canonicalWorkspacePath = baseDir.getCanonicalPath();
    final String canonicalRepositoryBaseDir =
         r.getDirectory().getParentFile().getCanonicalPath();

    String repoPath = canonicalWorkspacePath.substring(
         canonicalRepositoryBaseDir.length());
    if (! repoPath.startsWith("/"))
    {
      repoPath = '/' + repoPath;
    }

    getProject().setProperty(repositoryTypePropertyName, "git");
    getProject().setProperty(repositoryURLPropertyName, repoURL);
    getProject().setProperty(repositoryPathPropertyName, repoPath);
    getProject().setProperty(repositoryRevisionPropertyName, repoRevision);
    getProject().setProperty(repositoryRevisionNumberPropertyName, "-1");
  }



  /**
   * Obtains information about the subversion repository from which the LDAP SDK
   * source was obtained.
   *
   * @throws  Exception  If a problem is encountered while attempting to obtain
   *                     information about the subversion repository.
   */
  private void getSubversionInfo()
          throws Exception
  {
    final SVNWCClient svn =
         new SVNWCClient((ISVNAuthenticationManager) null, null);
    final SVNInfo svnInfo = svn.doInfo(baseDir, SVNRevision.WORKING);

    final String repoURL = svnInfo.getURL().toString();
    final String repoPath = svnInfo.getURL().getPath();
    final String repoRevision =
         String.valueOf(svnInfo.getRevision().getNumber());

    getProject().setProperty(repositoryTypePropertyName, "subversion");
    getProject().setProperty(repositoryURLPropertyName, repoURL);
    getProject().setProperty(repositoryPathPropertyName, repoPath);
    getProject().setProperty(repositoryRevisionPropertyName, repoRevision);
    getProject().setProperty(repositoryRevisionNumberPropertyName,
         repoRevision);
  }
}
