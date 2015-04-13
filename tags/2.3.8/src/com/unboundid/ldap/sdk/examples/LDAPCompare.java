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



import java.io.OutputStream;
import java.io.Serializable;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;

import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.CompareResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.Base64;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;



/**
 * This class provides a simple tool that can be used to perform compare
 * operations in an LDAP directory server.  All of the necessary information is
 * provided using command line arguments.    Supported arguments include those
 * allowed by the {@link LDAPCommandLineTool} class.  In addition, a set of at
 * least two unnamed trailing arguments must be given.  The first argument
 * should be a string containing the name of the target attribute followed by a
 * colon and the assertion value to use for that attribute (e.g.,
 * "cn:john doe").  Alternately, the attribute name may be followed by two
 * colons and the base64-encoded representation of the assertion value
 * (e.g., "cn::  am9obiBkb2U=").  Any subsequent trailing arguments will be the
 * DN(s) of entries in which to perform the compare operation(s).
 * <BR><BR>
 * Some of the APIs demonstrated by this example include:
 * <UL>
 *   <LI>Argument Parsing (from the {@code com.unboundid.util.args}
 *       package)</LI>
 *   <LI>LDAP Command-Line Tool (from the {@code com.unboundid.util}
 *       package)</LI>
 *   <LI>LDAP Communication (from the {@code com.unboundid.ldap.sdk}
 *       package)</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPCompare
       extends LDAPCommandLineTool
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 719069383330181184L;



  // The argument parser for this tool.
  private ArgumentParser parser;



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
    final LDAPCompare ldapCompare = new LDAPCompare(outStream, errStream);
    return ldapCompare.runTool(args);
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
  public LDAPCompare(final OutputStream outStream, final OutputStream errStream)
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
    return "ldapcompare";
  }



  /**
   * Retrieves the description for this tool.
   *
   * @return  The description for this tool.
   */
  @Override()
  public String getToolDescription()
  {
    return "Process compare operations in LDAP directory server.";
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
   * Retrieves the maximum number of unnamed trailing arguments that are
   * allowed.
   *
   * @return  A negative value to indicate that any number of trailing arguments
   *          may be provided.
   */
  @Override()
  public int getMaxTrailingArguments()
  {
    return -1;
  }



  /**
   * Retrieves a placeholder string that may be used to indicate what kinds of
   * trailing arguments are allowed.
   *
   * @return  A placeholder string that may be used to indicate what kinds of
   *          trailing arguments are allowed.
   */
  @Override()
  public String getTrailingArgumentsPlaceholder()
  {
    return "attr:value dn1 [dn2 [dn3 [...]]]";
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
    // No additional named arguments are required, but we should save a
    // reference to the argument parser.
    this.parser = parser;
  }



  /**
   * Performs the actual processing for this tool.  In this case, it gets a
   * connection to the directory server and uses it to perform the requested
   * comparisons.
   *
   * @return  The result code for the processing that was performed.
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    // Make sure that at least two trailing arguments were provided, which will
    // be the attribute value assertion and at least one entry DN.
    final List<String> trailingArguments = parser.getTrailingArguments();
    if (trailingArguments.isEmpty())
    {
      err("No attribute value assertion was provided.");
      err();
      err(parser.getUsageString(79));
      return ResultCode.PARAM_ERROR;
    }
    else if (trailingArguments.size() == 1)
    {
      err("No target entry DNs were provided.");
      err();
      err(parser.getUsageString(79));
      return ResultCode.PARAM_ERROR;
    }


    // Parse the attribute value assertion.
    final String avaString = trailingArguments.get(0);
    final int colonPos = avaString.indexOf(':');
    if (colonPos <= 0)
    {
      err("Malformed attribute value assertion.");
      err();
      err(parser.getUsageString(79));
      return ResultCode.PARAM_ERROR;
    }

    final String attributeName = avaString.substring(0, colonPos);
    final byte[] assertionValueBytes;
    final int doubleColonPos = avaString.indexOf("::");
    if (doubleColonPos == colonPos)
    {
      // There are two colons, so it's a base64-encoded assertion value.
      try
      {
        assertionValueBytes = Base64.decode(avaString.substring(colonPos+2));
      }
      catch (ParseException pe)
      {
        err("Unable to base64-decode the assertion value:  ",
                    pe.getMessage());
        err();
        err(parser.getUsageString(79));
        return ResultCode.PARAM_ERROR;
      }
    }
    else
    {
      // There is only a single colon, so it's a simple UTF-8 string.
      assertionValueBytes =
           StaticUtils.getBytes(avaString.substring(colonPos+1));
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


    // For each of the target entry DNs, process the compare.
    ResultCode resultCode = ResultCode.SUCCESS;
    CompareRequest compareRequest = null;
    for (int i=1; i < trailingArguments.size(); i++)
    {
      final String targetDN = trailingArguments.get(i);
      if (compareRequest == null)
      {
        compareRequest = new CompareRequest(targetDN, attributeName,
                                            assertionValueBytes);
      }
      else
      {
        compareRequest.setDN(targetDN);
      }

      try
      {
        out("Processing compare request for entry ", targetDN);
        final CompareResult result = connection.compare(compareRequest);
        if (result.compareMatched())
        {
          out("The compare operation matched.");
        }
        else
        {
          out("The compare operation did not match.");
        }
      }
      catch (LDAPException le)
      {
        resultCode = le.getResultCode();
        err("An error occurred while processing the request:  ",
            le.getMessage());
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
      }
      out();
    }


    // Close the connection to the directory server and exit.
    connection.close();
    out();
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

    final String[] args =
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--bindDN", "uid=admin,dc=example,dc=com",
      "--bindPassword", "password",
      "givenName:John",
      "uid=jdoe,ou=People,dc=example,dc=com"
    };
    final String description =
         "Attempt to determine whether the entry for user " +
         "'uid=jdoe,ou=People,dc=example,dc=com' has a value of 'John' for " +
         "the givenName attribute.";
    examples.put(args, description);

    return examples;
  }
}
