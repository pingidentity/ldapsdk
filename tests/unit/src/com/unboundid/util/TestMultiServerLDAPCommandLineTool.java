/*
 * Copyright 2012-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2017 Ping Identity Corporation
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
package com.unboundid.util;



import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;



/**
 * This class provides an implementation of a multi-server LDAP command line
 * tool that can be used for testing purposes.
 */
public final class TestMultiServerLDAPCommandLineTool
       extends MultiServerLDAPCommandLineTool
{
  // The argument parser for this tool.
  private ArgumentParser parser = null;



  /**
   * Creates a new instance of this command-line tool with the provided
   * information.
   *
   * @param  namePrefixes  The prefixes to use for argument names, if any.
   * @param  nameSuffixes  The suffixes to use for argument names, if any.
   */
  public TestMultiServerLDAPCommandLineTool(final String[] namePrefixes,
                                            final String[] nameSuffixes)
  {
    super(null,null,namePrefixes, nameSuffixes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolName()
  {
    return "Test Multi-Server Tool";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolDescription()
  {
    return "This is a test of a multi-server tool.";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolVersion()
  {
    return "1.2.3";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    this.parser = parser;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    return ResultCode.SUCCESS;
  }



  /**
   * Retrieves the argument parser used for this tool.
   *
   * @return  The argument parser used for this tool.
   */
  public ArgumentParser getArgumentParser()
  {
    return parser;
  }
}
