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
package com.unboundid.buildtools.repositoryinfo;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.StringTokenizer;

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
  // Indicates whether the task should exit with an error if the repository
  // information cannot be obtained.
  private Boolean failOnError;

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
    failOnError                          = Boolean.FALSE;
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
   * Specifies whether this task should exit with an error if the repository
   * information cannot be obtained.
   *
   * @param  failOnError  If this is {@code Boolean.TRUE} and the repository
   *                      information cannot be obtained, then the
   *                      {@link #execute()} method will throw a
   *                      {@code BuildException}, causing the task to fail.  If
   *                      this is {@code Boolean.FALSE} and the repository
   *                      information cannot be obtained, then the task will use
   *                      generic repository information and the {@code execute}
   *                      method will return normally.
   */
  public void setFailOnError(final Boolean failOnError)
  {
    if (failOnError == null)
    {
      throw new BuildException("failOnError must not be null");
    }
    else if (failOnError.equals(Boolean.TRUE))
    {
      this.failOnError = Boolean.TRUE;
    }
    else if (failOnError.equals(Boolean.TRUE))
    {
      this.failOnError = Boolean.FALSE;
    }
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
      final File dotGitDir = new File(f, ".git");
      if (dotGitDir.exists())
      {
        try
        {
          getGitInfoViaJGit();
          return;
        }
        catch (final Exception e)
        {
          if (failOnError == Boolean.TRUE)
          {
            throw new BuildException(
                 "ERROR:  Unable to obtain repository details from the git " +
                      "workspace in directory " + f.getAbsolutePath() + ":  " +
                      e,
                 e);
          }
          else
          {
            System.err.println("ERROR:  Unable to obtain repository details " +
                 "from the git workspace in directory " + f.getAbsolutePath() +
                 ":  " + e + ".  Using generic fallback repository info.");
          }
        }
        catch (final UnsupportedClassVersionError e)
        {
          try
          {
            getGitInfoViaCommandLine();
            return;
          }
          catch (final Exception e2)
          {
            try
            {
              getGitInfoFromDotGitDirectory(dotGitDir);
              return;
            }
            catch (final Exception e3)
            {
              if (failOnError == Boolean.TRUE)
              {
                throw new BuildException(
                     "ERROR:  Unable to obtain repository details from the " +
                          "git workspace in directory " + f.getAbsolutePath() +
                          " using jgit (which is only supported on Java " +
                          "version 8 or higher), from the git command-line " +
                          "utility, or by examining files in the .git " +
                          "directory tree.  The jgit failure was:  " + e +
                          ".  The command-line failure was:  " + e2 +
                          ".  The filesystem failure was:  " + e3,
                     e3);
              }
              else
              {
                System.err.println("ERROR:  Unable to obtain repository " +
                     "details from the git workspace in directory " +
                     f.getAbsolutePath() + " using jgit (which is only " +
                     "supported on Java version 8 or higher), from the git " +
                     "command-line utility, or by examining files in the " +
                     ".git directory tree.  The jgit failure was:  " + e +
                     ".  The command-line failure was:  " + e2 +
                     ".  The filesystem failure was:  " + e3 +
                     ".  Using generic repository fallback info.");
              }
            }
          }
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
          if (failOnError == Boolean.TRUE)
          {
            throw new BuildException(
                 "ERROR:  Unable to obtain repository details from the " +
                      "subversion workspace in directory " +
                      f.getAbsolutePath() + ":  " + e,
                 e);
          }
          else
          {
            System.err.println("ERROR:  Unable to obtain repository details " +
                 "from the subversion workspace in directory " +
                 f.getAbsolutePath() + ":  " + e +
                 ".  Using fallback repository info.");
          }
        }
      }

      f = f.getAbsoluteFile().getParentFile();
    }

    if (failOnError == Boolean.TRUE)
    {
      throw new BuildException("ERROR:  Unable to obtain any repository " +
           "information for the data in " + baseDir.getAbsolutePath() +
           " because it could not be identified as coming from either a git " +
           "or a subversion repository.");
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
   * Attempts to use the jgit library to obtain information about the git
   * repository from which the LDAP SDK source was obtained.
   *
   * @throws  Exception  If a problem is encountered while attempting to obtain
   *                     information about the git repository.
   */
  private void getGitInfoViaJGit()
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
   * Attempts to use the git command-line tool to obtain information about the
   * git repository from which the LDAP SDK source was obtained.
   *
   * @throws  Exception  If a problem is encountered while attempting to obtain
   *                     information about the git repository.
   */
  private void getGitInfoViaCommandLine()
          throws Exception
  {
    // Invoke the command "git remote get-url origin" to get the repository URL.
    final String repoURL = invokeGitCommand("remote", "get-url", "origin");

    // Invoke the command "git log --max-count=1 --pretty=format:%H" to get the
    // repository revision.
    final String repoRevision = invokeGitCommand("log", "--max-count=1",
         "--pretty=format:%H");

    getProject().setProperty(repositoryTypePropertyName, "git");
    getProject().setProperty(repositoryURLPropertyName, repoURL);
    getProject().setProperty(repositoryPathPropertyName, "/");
    getProject().setProperty(repositoryRevisionPropertyName, repoRevision);
    getProject().setProperty(repositoryRevisionNumberPropertyName, "-1");
  }



  /**
   * Attempts to examine files in the .git directory on the filesystem to obtain
   * information about the git repository from which the LDAP SDK source was
   * obtained.
   *
   * @param  dotGitDir  The path to the ".git" directory for the workspace.
   *
   * @throws  Exception  If a problem is encountered while attempting to obtain
   *                     information about the git repository.
   */
  private void getGitInfoFromDotGitDirectory(final File dotGitDir)
          throws Exception
  {
    final File refsDir = new File(dotGitDir, "refs");
    final File headsDir = new File(refsDir, "heads");
    final File refsHeadsMasterFile = new File(headsDir, "master");

    final File masterFile;
    if (refsHeadsMasterFile.exists() && refsHeadsMasterFile.isFile())
    {
      masterFile = refsHeadsMasterFile;
    }
    else
    {
      final File remotesDir = new File(refsDir, "remotes");
      final File originDir = new File(remotesDir, "origin");
      final File refsRemotesOriginMasterFile = new File(originDir, "master");
      if (refsRemotesOriginMasterFile.exists() &&
           refsRemotesOriginMasterFile.isFile())
      {
        masterFile = refsRemotesOriginMasterFile;
      }
      else
      {
        throw new BuildException("ERROR:  Unable to obtain the repository " +
             "revision from the .git directory tree because neither '" +
             refsHeadsMasterFile.getAbsolutePath() + "' nor '" +
             refsRemotesOriginMasterFile.getAbsolutePath() + "' exists.");
      }
    }

    final String repoRevision;
    try (FileReader fileReader = new FileReader(masterFile);
         BufferedReader bufferedReader = new BufferedReader(fileReader))
    {
      repoRevision = bufferedReader.readLine();
      if ((repoRevision == null) || repoRevision.isEmpty())
      {
        throw new BuildException("ERROR:  Expected master revision file '" +
             masterFile.getAbsolutePath() +
             "' is empty or has an empty first line.");
      }
    }

    final File configFile = new File(dotGitDir, "config");
    if (! (configFile.exists() && configFile.isFile()))
    {
      throw new BuildException("ERROR:  Expected config file '" +
           configFile.getAbsolutePath() + "' does not exist or is not a file.");
    }

    String repoURL = null;
    try (FileReader fileReader = new FileReader(configFile);
         BufferedReader bufferedReader = new BufferedReader(fileReader))
    {
      while (true)
      {
        final String line = bufferedReader.readLine();
        if (line == null)
        {
          if (repoURL == null)
          {
            throw new BuildException("ERROR:  End of config file '" +
                 configFile.getAbsolutePath() +
                 "' reached without finding the repository URL.");
          }
          else
          {
            break;
          }
        }

        if (line.indexOf("url") < 0)
        {
          continue;
        }

        final StringTokenizer tokenizer = new StringTokenizer(line, " \t=");
        final String firstToken = tokenizer.nextToken();
        if (firstToken.equalsIgnoreCase("url"))
        {
          if (tokenizer.hasMoreTokens())
          {
            if (repoURL != null)
            {
              throw new BuildException("ERROR:  Config file '" +
                   configFile.getAbsolutePath() +
                   "' unexpectedly has multiple 'url' elements.");
            }

            repoURL = tokenizer.nextToken();
            if ((repoURL == null) || repoURL.isEmpty())
            {
              throw new BuildException("ERROR:  Config file '" +
                   configFile.getAbsolutePath() +
                   "' contains line '" + line +  "' without a URL value.");
            }
            else if (tokenizer.hasMoreTokens())
            {
              throw new BuildException("ERROR:  Config file '" +
                   configFile.getAbsolutePath() +
                   "' contains line '" + line +  "' with multiple URL values.");
            }
          }
        }
      }
    }

    getProject().setProperty(repositoryTypePropertyName, "git");
    getProject().setProperty(repositoryURLPropertyName, repoURL);
    getProject().setProperty(repositoryPathPropertyName, "/");
    getProject().setProperty(repositoryRevisionPropertyName, repoRevision);
    getProject().setProperty(repositoryRevisionNumberPropertyName, "-1");
  }



  /**
   * Invokes the git command, if the command succeeds and produces a single line
   * of output, returns that line.
   *
   * @param  args  The command-line arguments to provide to the git command.
   *
   * @return  The single line of output (without any line breaks) produced by
   *          the git command.
   *
   * @throws  Exception  If a problem is encountered while trying to run the
   *                     git command, if the git command does not exit cleanly,
   *                     or if it does not produce exactly one line of output.
   */
  private String invokeGitCommand(final String... args)
          throws Exception
  {
    final ArrayList<String> commandPlusArguments =
         new ArrayList<>(args.length + 1);
    final String osName = System.getProperty("os.name");
    if ((osName != null) && osName.toLowerCase().contains("windows"))
    {
      commandPlusArguments.add("git.exe");
    }
    else
    {
      if (new File("/usr/bin/git").exists())
      {
        commandPlusArguments.add("/usr/bin/git");
      }
      else if (new File("/bin/git").exists())
      {
        commandPlusArguments.add("/bin/git");
      }
      else if (new File("/usr/local/bin/git").exists())
      {
        commandPlusArguments.add("/usr/local/bin/git");
      }
      else
      {
        commandPlusArguments.add("git");
      }
    }

    commandPlusArguments.addAll(Arrays.asList(args));

    final ProcessBuilder processBuilder =
         new ProcessBuilder(commandPlusArguments);
    processBuilder.directory(baseDir);
    processBuilder.redirectOutput(ProcessBuilder.Redirect.PIPE);
    processBuilder.redirectErrorStream(true);

    System.out.println("Invoking command " + commandPlusArguments);

    final Process gitProcess = processBuilder.start();
    try
    {
      final BufferedReader outputReader = new BufferedReader(
           new InputStreamReader(gitProcess.getInputStream()));
      final ArrayList<String> outputLines = new ArrayList<>(10);

      final long stopWaitingTime = System.currentTimeMillis() + 30_000L;
      while (true)
      {
        if (System.currentTimeMillis() > stopWaitingTime)
        {
          throw new BuildException("ERROR:  Command " + commandPlusArguments +
               " did not complete after 30 seconds.");
        }

        while (outputReader.ready() &&
             (System.currentTimeMillis() <= stopWaitingTime))
        {
          final String line = outputReader.readLine();
          if (line == null)
          {
            break;
          }

          outputLines.add(line);
        }

        final int exitCode;
        try
        {
          exitCode = gitProcess.exitValue();
        }
        catch (final Exception e)
        {
          Thread.sleep(10L);
          continue;
        }

        if (exitCode == 0)
        {
          switch (outputLines.size())
          {
            case 0:
              throw new BuildException("ERROR:  Running command " +
                   commandPlusArguments + " completed with exit code zero " +
                   "but no output.  Exactly one line of output was expected.");

            case 1:
              return outputLines.get(0);

            default:
              throw new BuildException("ERROR:  Running command " +
                   commandPlusArguments + " completed with exit code zero " +
                   "but multiple lines of output when exactly one output " +
                   "line was expected.  The output lines were:  " +
                   outputLines);
          }
        }
      }
    }
    finally
    {
      gitProcess.destroy();
    }
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
