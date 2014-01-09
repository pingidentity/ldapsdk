/*
 * Copyright 2009-2014 UnboundID Corp.
 * All Rights Reserved.
 */
package com.unboundid.buildtools.copydocs;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;



/**
 * This class provides an Ant task that can be used to copy the LDAP SDK
 * documentation into place.  The documentation will be in HTML form, but will
 * contain only the main content for the page.  The configuration for the task
 * will provide source and destination directories, a file containing the
 * header, a file containing the footer, and the extension to use for the file.
 * <BR><BR>
 * Only source files with an ".html" extension will be processed.  All other
 * files will be copied as-is with no processing.  All directories will be
 * processed recursively, and any ".svn" directories will be ignored.
 * <BR><BR>
 * All lines in the header, body, and footer will be processed.  The following
 * tokens can be embedded in any of the header, body, or footer text to trigger
 * special action:
 * <UL>
 *   <LI>
 *     <CODE>${BASE}</CODE> -- This will be replaced with a value that is based
 *     on the current depth in the documentation.  For documents in the
 *     top-level directory, it will be replaced with an empty string.  For
 *     documents exactly one level below the top level, it will be replaced with
 *     "../".  For documents two levels below the top level, it will be replaced
 *     with "../../".  And so on.  This can be used to build relative paths.
 *     <BR><BR>
 *   </LI>
 *   <LI>
 *     <CODE>${YEAR}</CODE> -- This will be replaced with the four-digit
 *     representation of the current year.
 *     <BR><BR>
 *   </LI>
 *   <LI>
 *     <CODE>${EXTENSION}</CODE> -- This will be replaced with the value
 *     provided in the "extension" task property (i.e., the file extension used
 *     for the generated documentation).
 *     <BR><BR>
 *   </LI>
 *   <LI>
 *     <CODE>${TARGET="target"}</CODE> -- This indicates that the line
 *     containing this token will only appear in documentation generated with a
 *     target of "target".  In that case, only this token will be removed and
 *     the rest of the line will be processed normally.  If the target provided
 *     for this task is not "target", then the entire line will be excluded from
 *     the documentation.  At present, the value for target may be either
 *     "offline" or "website".
 *     <BR><BR>
 *   </LI>
 * </UL>
 *
 *
 * If the header and footer need to include any relative paths, then they should
 * use the token "${BASE}", which will be replaced with an empty string for
 * files in the top-level directory, a value of ".." for files in a directory
 * immediately below the top-level directory, "../.." for files one level below
 * that, and so on.  The header and footer files may also use the token
 * "${YEAR}" to be replaced with the four-digit representation of the current
 * year.
 */
public class CopyDocs
       extends Task
{
  // The path to the directory into which the documentation will be copied.
  private File destinationDir;

  // The path to the file containing the footer to append to the files.
  private File footerFile;

  // The path to the file containing the header to prepend to the files.
  private File headerFile;

  // The path to the directory containing the documentation source files.
  private File sourceDir;

  // The lines that comprise the footer to append to each page.
  private LinkedList<String> footerLines;

  // The lines that comprise the header to prepend to each page.
  private LinkedList<String> headerLines;

  // The extension to use for files that are processed.
  private String extension;

  // The target that indicates the ultimate location for the generated
  // documentation.  The value may be either "offline" if the documentation
  // should be generated for offline use or "website" if the documentation will
  // be placed on the www.unboundid.com website.
  private String target;

  // The four-digit representation of the current year.
  private String year;



  /**
   * Creates a new instance of this task.
   */
  public CopyDocs()
  {
    destinationDir = null;
    footerFile     = null;
    headerFile     = null;
    sourceDir      = null;
    extension      = null;
    target         = null;
  }



  /**
   * Specifies the path to the directory containing the source files.
   *
   * @param  sourceDir  The path to the directory containing the source files.
   */
  public void setSourceDir(final File sourceDir)
  {
    this.sourceDir = sourceDir;
  }



  /**
   * Specifies the path to the directory containing the destination files.
   *
   * @param  destinationDir  The path to the directory containing the
   *                         destination files.
   */
  public void setDestinationDir(final File destinationDir)
  {
    this.destinationDir = destinationDir;
  }



  /**
   * Specifies the path to the file containing the header to prepend to the
   * source files.
   *
   * @param  headerFile  The path to the file containing the header to prepend
   *                     to the source files.
   */
  public void setHeaderFile(final File headerFile)
  {
    this.headerFile = headerFile;
  }



  /**
   * Specifies the path to the file containing the footer to append to the
   * source files.
   *
   * @param  footerFile  The path to the file containing the footer to prepend
   *                     to the source files.
   */
  public void setFooterFile(final File footerFile)
  {
    this.footerFile = footerFile;
  }



  /**
   * Specifies the extension to use for the destination files.
   *
   * @param  extension  The extension to use for the destination files.
   */
  public void setExtension(final String extension)
  {
    this.extension = extension;
  }



  /**
   * Specifies the ultimate target location for the generated documentation.
   *
   * @param  target  The ultimate target location for the generated
   *                 documentation.
   */
  public void setTarget(final String target)
  {
    this.target = target;
  }



  /**
   * Performs the processing for this task.
   *
   * @throws  BuildException  If a problem occurs during processing.
   */
  @Override()
  public void execute()
         throws BuildException
  {
    if (sourceDir == null)
    {
      throw new BuildException("No sourceDir specified");
    }

    if (destinationDir == null)
    {
      throw new BuildException("No destinationDir specified");
    }

    if (headerFile == null)
    {
      throw new BuildException("No headerFile specified");
    }

    if (footerFile == null)
    {
      throw new BuildException("No footerFile specified");
    }

    if (extension == null)
    {
      throw new BuildException("No extension specified");
    }

    if (target == null)
    {
      throw new BuildException("No target specified (must be either " +
                               "'offline' or 'website')");
    }
    else if (! (target.equals("offline") || target.equals("website")))
    {
      throw new BuildException("Invalid target specified (must be either " +
                               "'offline' or 'website')");
    }


    year = new SimpleDateFormat("yyyy").format(new Date());

    headerLines = readFile(headerFile);
    footerLines = readFile(footerFile);

    processDirectory(sourceDir, destinationDir, "");
  }



  /**
   * Processes all files in the specified source directory and writes the output
   * to the specified destination directory.
   *
   * @param  s  The path to the source directory.
   * @param  d  The path to the destination directory.
   * @param  b  The string to use in place of the "${BASE}" token.
   *
   * @throws  BuildException  If a problem occurs during processing.
   */
  private void processDirectory(final File s, final File d, final String b)
          throws BuildException
  {
    for (File file : s.listFiles())
    {
      if (file.isDirectory())
      {
        if (file.getName().equals(".svn"))
        {
          continue;
        }

        File targetDir = new File(d, file.getName());
        if (! targetDir.mkdirs())
        {
          throw new BuildException("Unable to create directory " +
                                   targetDir.getAbsolutePath());
        }

        processDirectory(file, targetDir, "../" + b);
      }
      else if (file.getName().endsWith(".html"))
      {
        int dotPos = file.getName().lastIndexOf('.');
        String newName = file.getName().substring(0, dotPos) + '.' + extension;
        File targetFile = new File(d, newName);

        PrintWriter w = null;

        try
        {
          w = new PrintWriter(new FileWriter(targetFile));

          for (String line : headerLines)
          {
            String l = processLine(line, b);
            if (l != null)
            {
              w.println(l);
            }
          }

          for (String line : readFile(file))
          {
            String l = processLine(line, b);
            if (l != null)
            {
              w.println(l);
            }
          }

          for (String line : footerLines)
          {
            String l = processLine(line, b);
            if (l != null)
            {
              w.println(l);
            }
          }
        }
        catch (Exception e)
        {
          throw new BuildException("Error processing doc file " +
                                   file.getAbsolutePath() + ":  " + e, e);
        }
        finally
        {
          if (w != null)
          {
            w.close();
          }
        }
      }
      else
      {
        copyFile(file, d);
      }
    }
  }



  /**
   * Performs any necessary processing for the provided line.
   *
   * @param  line  The line to be processed.
   * @param  base  The value to use in place of the "${BASE}" token.
   *
   * @return  The processed line.
   */
  private String processLine(final String line, final String base)
  {
    String l = line;
    if (l.contains("${TARGET=\"" + target + "\"}"))
    {
      l = l.replace("${TARGET=\"" + target + "\"}", "");
    }

    if (l.contains("${TARGET="))
    {
      return null;
    }

    l = l.replace("${BASE}", base);
    l = l.replace("${YEAR}", year);
    l = l.replace("${EXTENSION}", extension);

    return l;
  }



  /**
   * Reads the contents of the specified file into a list.
   *
   * @param  f  The file to be read.
   *
   * @return  The contents of the file to be read.
   *
   * @throws  BuildException  If an error occurs while reading the file.
   */
  private static LinkedList<String> readFile(final File f)
          throws BuildException
  {

    BufferedReader r = null;
    try
    {
      r = new BufferedReader(new FileReader(f));
      LinkedList<String> lines = new LinkedList<String>();

      while (true)
      {
        String line = r.readLine();
        if (line == null)
        {
          break;
        }

        lines.add(line);
      }

      return lines;
    }
    catch (Exception e)
    {
      throw new BuildException("Error reading file " + f.getAbsolutePath() +
                               ":  " + e, e);
    }
    finally
    {
      try
      {
        if (r != null)
        {
          r.close();
        }
      }
      catch (Exception e)
      {
        System.err.println("Error closing file " + f.getAbsolutePath() +
                           ":  " + e);
      }
    }
  }



  /**
   * Copies the specified source file into the destination directory.
   *
   * @param  f  The file to be copied.
   * @param  d  The directory into which the file should be written.
   *
   * @throws  BuildException  If a problem occurs while copying the file.
   */
  private static void copyFile(final File f, final File d)
          throws BuildException
  {
    FileInputStream  i = null;
    FileOutputStream o = null;

    byte[] buffer = new byte[8192];
    File t = new File(d, f.getName());

    try
    {

      i = new FileInputStream(f);
      o = new FileOutputStream(t);

      while (true)
      {
        int bytesRead = i.read(buffer);
        if (bytesRead < 0)
        {
          break;
        }

        o.write(buffer, 0, bytesRead);
      }
    }
    catch (Exception e)
    {
      throw new BuildException("Error processing file " + f.getAbsolutePath() +
                               ":  " + e, e);
    }
    finally
    {
      if (i != null)
      {
        try
        {
          i.close();
        }
        catch (Exception e)
        {
          System.err.println("Error closing file " + f.getAbsolutePath());
        }
      }

      if (o != null)
      {
        try
        {
          o.close();
        }
        catch (Exception e)
        {
          System.err.println("Error closing file " + t.getAbsolutePath());
        }
      }
    }
  }
}
