/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import java.io.OutputStream;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentListArgument;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.BooleanValueArgument;
import com.unboundid.util.args.ControlArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.DurationArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.FilterArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.ScopeArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.args.TimestampArgument;



/**
 * This class provides an implementation of a command-line tool that can be used
 * for testing purposes.
 */
public final class TestLDAPCommandLineTool
       extends LDAPCommandLineTool
{
  // The arguments used by this program.
  private volatile ArgumentListArgument singleValuedArgumentListArgument;
  private volatile ArgumentListArgument multiValuedArgumentListArgument;
  private volatile BooleanArgument booleanArgument;
  private volatile BooleanValueArgument booleanValueArgument;
  private volatile ControlArgument singleValuedControlArgument;
  private volatile ControlArgument multiValuedControlArgument;
  private volatile DNArgument singleValuedDNArgument;
  private volatile DNArgument multiValuedDNArgument;
  private volatile DurationArgument durationArgument;
  private volatile FileArgument singleValuedFileArgument;
  private volatile FileArgument multiValuedFileArgument;
  private volatile FilterArgument singleValuedFilterArgument;
  private volatile FilterArgument multiValuedFilterArgument;
  private volatile IntegerArgument singleValuedIntegerArgument;
  private volatile IntegerArgument multiValuedIntegerArgument;
  private volatile IntegerArgument resultCodeArgument;
  private volatile ScopeArgument scopeArgument;
  private volatile StringArgument singleValuedStringArgument;
  private volatile StringArgument multiValuedOpenOptionsStringArgument;
  private volatile StringArgument multiValuedFixedOptionsStringArgument;
  private volatile TimestampArgument singleValuedTimestampArgument;
  private volatile TimestampArgument multiValuedTimestampArgument;



  /**
   * Creates a new instance of this tool.
   *
   * @param  out  The standard output stream.
   * @param  err  The standard error stream.
   */
  public TestLDAPCommandLineTool(final OutputStream out,
                                 final OutputStream err)
  {
    super(out, err);

    singleValuedArgumentListArgument      = null;
    multiValuedArgumentListArgument       = null;
    booleanArgument                       = null;
    booleanValueArgument                  = null;
    singleValuedControlArgument           = null;
    multiValuedControlArgument            = null;
    singleValuedDNArgument                = null;
    multiValuedDNArgument                 = null;
    durationArgument                      = null;
    singleValuedFileArgument              = null;
    multiValuedFileArgument               = null;
    singleValuedFilterArgument            = null;
    multiValuedFilterArgument             = null;
    singleValuedTimestampArgument         = null;
    multiValuedTimestampArgument          = null;
    singleValuedIntegerArgument           = null;
    multiValuedIntegerArgument            = null;
    resultCodeArgument                    = null;
    scopeArgument                         = null;
    singleValuedStringArgument            = null;
    multiValuedOpenOptionsStringArgument  = null;
    multiValuedFixedOptionsStringArgument = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolName()
  {
    return "tool-name";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolDescription()
  {
    return "Tool Description";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    return Arrays.asList("Second Paragraph", "Third Paragraph");
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolVersion()
  {
    return "1.2.3.4";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean defaultsToInteractiveMode()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    final ArgumentParser argListParser1 = new ArgumentParser("argumentList1",
         "Argument List 1 Description");
    argListParser1.addArgument(new StringArgument(null, "foo", false, -1,
         "{foo}", "Foo Description"));

    final ArgumentParser argListParser2 = new ArgumentParser("argumentList2",
         "Argument List 2 Description");
    argListParser2.addArgument(new StringArgument(null, "bar", false, -1,
         "{bar}", "Bar Description"));

    singleValuedArgumentListArgument = new ArgumentListArgument(null,
         "singleValuedArgumentList", false, 1, "{argList}", "Argument List",
         argListParser1);
    parser.addArgument(singleValuedArgumentListArgument);

    multiValuedArgumentListArgument = new ArgumentListArgument(null,
         "multiValuedArgumentList", false, -1, "{argList}", "Argument List",
         argListParser2);
    parser.addArgument(multiValuedArgumentListArgument);

    booleanArgument = new BooleanArgument(null, "boolean",
         "Boolean Description");
    parser.addArgument(booleanArgument);

    booleanValueArgument = new BooleanValueArgument(null, "booleanValue",
         false, "{true|false}", "Boolean Value Description");
    parser.addArgument(booleanValueArgument);

    singleValuedControlArgument = new ControlArgument(null,
         "singleValuedControl", false, 1, null, "Control Description");
    parser.addArgument(singleValuedControlArgument);

    multiValuedControlArgument = new ControlArgument(null,
         "multiValuedControl", false, -1, null, "Control Description");
    parser.addArgument(multiValuedControlArgument);

    singleValuedDNArgument = new DNArgument(null, "singleValuedDN", false, 1,
         "{dn}", "DN Description");
    parser.addArgument(singleValuedDNArgument);

    multiValuedDNArgument = new DNArgument(null, "multiValuedDN", false, -1,
         "{dn}", "DN Description");
    parser.addArgument(multiValuedDNArgument);

    durationArgument = new DurationArgument(null, "duration", false,
         "{duration}", "Duration Description");
    parser.addArgument(durationArgument);

    singleValuedFileArgument = new FileArgument(null, "singleValuedFile", false,
         1, "{path}", "File Description", false, true, true, false);
    parser.addArgument(singleValuedFileArgument);

    multiValuedFileArgument = new FileArgument(null, "multiValuedFile", false,
         -1, "{path}", "File Description", false, false, false, false);
    parser.addArgument(multiValuedFileArgument);

    singleValuedFilterArgument = new FilterArgument(null, "singleValuedFilter",
         false, 1, "{filter}", "Filter Description");
    parser.addArgument(singleValuedFilterArgument);

    multiValuedFilterArgument = new FilterArgument(null, "multiValuedFilter",
         false, -1, "{filter}", "Filter Description");
    parser.addArgument(multiValuedFilterArgument);

    singleValuedTimestampArgument = new TimestampArgument(null,
         "singleValuedGeneralizedTime", false, 1, "{timestamp}",
         "Generalized Time Description");
    parser.addArgument(singleValuedTimestampArgument);

    multiValuedTimestampArgument = new TimestampArgument(null,
         "multiValuedGeneralizedTime", false, -1, "{timestamp}",
         "Generalized Time Description");
    parser.addArgument(multiValuedTimestampArgument);

    singleValuedIntegerArgument = new IntegerArgument(null,
         "singleValuedInteger", false, 1, "{int}", "Integer Description");
    parser.addArgument(singleValuedIntegerArgument);

    multiValuedIntegerArgument = new IntegerArgument(null,
         "multiValuedInteger", false, -1, "{int}", "Integer Description");
    parser.addArgument(multiValuedIntegerArgument);

    scopeArgument = new ScopeArgument(null, "scope", false, "{scope}",
         "Scope Description");
    parser.addArgument(scopeArgument);

    singleValuedStringArgument = new StringArgument(null, "singleValuedString",
         false, 1, "{string}", "String Description");
    parser.addArgument(singleValuedStringArgument);

    multiValuedOpenOptionsStringArgument = new StringArgument(null,
         "multiValuedOpenOptionsString",
         false, -1, "{string}", "String Description");
    parser.addArgument(multiValuedOpenOptionsStringArgument);

    final LinkedHashSet<String> allowedValues = new LinkedHashSet<String>(5);
    allowedValues.add("first");
    allowedValues.add("second");
    allowedValues.add("third");
    allowedValues.add("fourth");
    allowedValues.add("fifth");
    multiValuedFixedOptionsStringArgument = new StringArgument(null,
         "multiValuedFixedOptionsString",
         false, -1, "{string}", "String Description", allowedValues);
    parser.addArgument(multiValuedFixedOptionsStringArgument);

    resultCodeArgument = new IntegerArgument(null, "resultCode", true, 1,
         "{intValue}", "The result code");
    parser.addArgument(resultCodeArgument);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    return ResultCode.valueOf(resultCodeArgument.getValue());
  }
}
