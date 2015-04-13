/*
 * Copyright 2008-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2014 UnboundID Corp.
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
package com.unboundid.ldap.sdk.examples;



import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.LinkedHashMap;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;



/**
 * This class provides a simple tool that can be used to perform add, delete,
 * modify, and modify DN operations against an LDAP directory server.  The
 * changes to apply can be read either from standard input or from an LDIF file.
 * <BR><BR>
 * Some of the APIs demonstrated by this example include:
 * <UL>
 *   <LI>Argument Parsing (from the {@code com.unboundid.util.args}
 *       package)</LI>
 *   <LI>LDAP Command-Line Tool (from the {@code com.unboundid.util}
 *       package)</LI>
 *   <LI>LDIF Processing (from the {@code com.unboundid.ldif} package)</LI>
 * </UL>
 * <BR><BR>
 * The behavior of this utility is controlled by command line arguments.
 * Supported arguments include those allowed by the {@link LDAPCommandLineTool}
 * class, as well as the following additional arguments:
 * <UL>
 *   <LI>"-f {path}" or "--ldifFile {path}" -- specifies the path to the LDIF
 *       file containing the changes to apply.  If this is not provided, then
 *       changes will be read from standard input.</LI>
 *   <LI>"-a" or "--defaultAdd" -- indicates that any LDIF records encountered
 *       that do not include a changetype should be treated as add change
 *       records.  If this is not provided, then such records will be
 *       rejected.</LI>
 *   <LI>"-c" or "--continueOnError" -- indicates that processing should
 *       continue if an error occurs while processing an earlier change.  If
 *       this is not provided, then the command will exit on the first error
 *       that occurs.</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPModify
       extends LDAPCommandLineTool
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2602159836108416722L;



  // Indicates whether processing should continue even if an error has occurred.
  private BooleanArgument continueOnError;

  // Indicates whether LDIF records without a changetype should be considered
  // add records.
  private BooleanArgument defaultAdd;

  // The LDIF file to be processed.
  private FileArgument ldifFile;



  /**
   * Parse the provided command line arguments and make the appropriate set of
   * changes.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(final String[] args)
  {
    final ResultCode resultCode = main(args, System.out, System.err);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Parse the provided command line arguments and make the appropriate set of
   * changes.
   *
   * @param  args       The command line arguments provided to this program.
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   *
   * @return  A result code indicating whether the processing was successful.
   */
  public static ResultCode main(final String[] args,
                                final OutputStream outStream,
                                final OutputStream errStream)
  {
    final LDAPModify ldapModify = new LDAPModify(outStream, errStream);
    return ldapModify.runTool(args);
  }



  /**
   * Creates a new instance of this tool.
   *
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   */
  public LDAPModify(final OutputStream outStream, final OutputStream errStream)
  {
    super(outStream, errStream);
  }



  /**
   * Retrieves the name for this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  public String getToolName()
  {
    return "ldapmodify";
  }



  /**
   * Retrieves the description for this tool.
   *
   * @return  The description for this tool.
   */
  @Override()
  public String getToolDescription()
  {
    return "Perform add, delete, modify, and modify " +
           "DN operations in an LDAP directory server.";
  }



  /**
   * Retrieves the version string for this tool.
   *
   * @return  The version string for this tool.
   */
  @Override()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * Adds the arguments used by this program that aren't already provided by the
   * generic {@code LDAPCommandLineTool} framework.
   *
   * @param  parser  The argument parser to which the arguments should be added.
   *
   * @throws  ArgumentException  If a problem occurs while adding the arguments.
   */
  @Override()
  public void addNonLDAPArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    String description = "Treat LDIF records that do not contain a " +
                         "changetype as add records.";
    defaultAdd = new BooleanArgument('a', "defaultAdd", description);
    parser.addArgument(defaultAdd);


    description = "Attempt to continue processing additional changes if " +
                  "an error occurs.";
    continueOnError = new BooleanArgument('c', "continueOnError",
                                          description);
    parser.addArgument(continueOnError);


    description = "The path to the LDIF file containing the changes.  If " +
                  "this is not provided, then the changes will be read from " +
                  "standard input.";
    ldifFile = new FileArgument('f', "ldifFile", false, 1, "{path}",
                                description, true, false, true, false);
    parser.addArgument(ldifFile);
  }



  /**
   * Performs the actual processing for this tool.  In this case, it gets a
   * connection to the directory server and uses it to perform the requested
   * operations.
   *
   * @return  The result code for the processing that was performed.
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    // Set up the LDIF reader that will be used to read the changes to apply.
    final LDIFReader ldifReader;
    try
    {
      if (ldifFile.isPresent())
      {
        // An LDIF file was specified on the command line, so we will use it.
        ldifReader = new LDIFReader(ldifFile.getValue());
      }
      else
      {
        // No LDIF file was specified, so we will read from standard input.
        ldifReader = new LDIFReader(System.in);
      }
    }
    catch (IOException ioe)
    {
      err("I/O error creating the LDIF reader:  ", ioe.getMessage());
      return ResultCode.LOCAL_ERROR;
    }


    // Get the connection to the directory server.
    final LDAPConnection connection;
    try
    {
      connection = getConnection();
      out("Connected to ", connection.getConnectedAddress(), ':',
          connection.getConnectedPort());
    }
    catch (LDAPException le)
    {
      err("Error connecting to the directory server:  ", le.getMessage());
      return le.getResultCode();
    }


    // Attempt to process and apply the changes to the server.
    ResultCode resultCode = ResultCode.SUCCESS;
    while (true)
    {
      // Read the next change to process.
      final LDIFChangeRecord changeRecord;
      try
      {
        changeRecord = ldifReader.readChangeRecord(defaultAdd.isPresent());
      }
      catch (LDIFException le)
      {
        err("Malformed change record:  ", le.getMessage());
        if (! le.mayContinueReading())
        {
          err("Unable to continue processing the LDIF content.");
          resultCode = ResultCode.DECODING_ERROR;
          break;
        }
        else if (! continueOnError.isPresent())
        {
          resultCode = ResultCode.DECODING_ERROR;
          break;
        }
        else
        {
          // We can try to keep processing, so do so.
          continue;
        }
      }
      catch (IOException ioe)
      {
        err("I/O error encountered while reading a change record:  ",
            ioe.getMessage());
        resultCode = ResultCode.LOCAL_ERROR;
        break;
      }


      // If the change record was null, then it means there are no more changes
      // to be processed.
      if (changeRecord == null)
      {
        break;
      }


      // Apply the target change to the server.
      try
      {
        out("Processing ", changeRecord.getChangeType().toString(),
            " operation for ", changeRecord.getDN());
        changeRecord.processChange(connection);
        out("Success");
        out();
      }
      catch (LDAPException le)
      {
        err("Error:  ", le.getMessage());
        err("Result Code:  ", le.getResultCode().intValue(), " (",
            le.getResultCode().getName(), ')');
        if (le.getMatchedDN() != null)
        {
          err("Matched DN:  ", le.getMatchedDN());
        }

        if (le.getReferralURLs() != null)
        {
          for (final String url : le.getReferralURLs())
          {
            err("Referral URL:  ", url);
          }
        }

        err();
        if (! continueOnError.isPresent())
        {
          resultCode = le.getResultCode();
          break;
        }
      }
    }


    // Close the connection to the directory server and exit.
    connection.close();
    out("Disconnected from the server");
    return resultCode;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<String[],String>();

    String[] args =
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--bindDN", "uid=admin,dc=example,dc=com",
      "--bindPassword", "password",
      "--ldifFile", "changes.ldif"
    };
    String description =
         "Attempt to apply the add, delete, modify, and/or modify DN " +
         "operations contained in the 'changes.ldif' file against the " +
         "specified directory server.";
    examples.put(args, description);

    args = new String[]
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--bindDN", "uid=admin,dc=example,dc=com",
      "--bindPassword", "password",
      "--continueOnError",
      "--defaultAdd"
    };
    description =
         "Establish a connection to the specified directory server and then " +
         "wait for information about the add, delete, modify, and/or modify " +
         "DN operations to perform to be provided via standard input.  If " +
         "any invalid operations are requested, then the tool will display " +
         "an error message but will continue running.  Any LDIF record " +
         "provided which does not include a 'changeType' line will be " +
         "treated as an add request.";
    examples.put(args, description);

    return examples;
  }
}
