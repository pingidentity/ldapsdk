/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
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
 * Copyright (C) 2022-2024 Ping Identity Corporation
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
package com.unboundid.buildtools.graalvmnativeimageresources;



import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONBuffer;



/**
 * This class provides an Ant task that can be used to generate a
 * resource-config.json file that can be used with the GraalVM native-image tool
 * to indicate which non-class resources should be included in the image.  It
 * will include all non-class files from the build/classes directory.
 */
public final class GenerateGraalVMNativeImageResourceConfigJSON
       extends Task
{
  // The path to the build/classes directory.
  private File buildClassesDirectory;

  // The path to the output JSON file to create.
  private File outputJSONFile;



  /**
   * Creates a new instance of this task.
   */
  public GenerateGraalVMNativeImageResourceConfigJSON()
  {
    buildClassesDirectory = null;
    outputJSONFile = null;
  }



  /**
   * Specifies the path to the build/classes directory.
   *
   * @param  buildClassesDirectory  The path to the build/classes directory.
   */
  public void setBuildClassesDirectory(final File buildClassesDirectory)
  {
    this.buildClassesDirectory = buildClassesDirectory;
  }



  /**
   * Specifies the path to the output JSON file to create.
   *
   * @param  outputJSONFile  The path the to the output JSON file to write.
   */
  public void setOutputJSONFile(final File outputJSONFile)
  {
    this.outputJSONFile = outputJSONFile;
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
    final List<String> patterns = new ArrayList<>();
    final String  basePattern = "\\Q";
    for (final File f : buildClassesDirectory.listFiles())
    {
      processFile(f, basePattern, patterns);
    }

    final JSONBuffer jsonBuffer = new JSONBuffer(null, -1, true);
    jsonBuffer.beginObject();
    jsonBuffer.beginObject("resources");
    jsonBuffer.beginArray("includes");

    for (final String pattern : patterns)
    {
      jsonBuffer.beginObject();
      jsonBuffer.appendString("pattern", pattern);
      jsonBuffer.endObject();
    }

    jsonBuffer.endArray();
    jsonBuffer.endObject();
    jsonBuffer.endObject();

    try (FileOutputStream outputStream = new FileOutputStream(outputJSONFile))
    {
      jsonBuffer.writeTo(outputStream);
    }
    catch (final Exception e)
    {
      throw new BuildException(
           "Failed to write output file '" + outputJSONFile.getAbsolutePath() +
                "':  " + StaticUtils.getExceptionMessage(e),
           e);
    }
  }



  /**
   * Performs the appropriate processing for the specified  file.  If the file
   * is actually a directory, then its contents will be recursively processed.
   * If it is a file, and its name does not end with ".class", then an
   * appropriate pattern string for that file will be added to the provided
   * list.
   *
   * @param  file            The file to process.
   * @param  basePatternStr  The pattern string to prepend to the name of each
   *                         appropriate file that has been identified.
   * @param  patternList     A list that will be updated with all appropriate
   *                         patterns identified during processing.
   */
  private void processFile(final File file, final String basePatternStr,
                           final List<String> patternList)
  {
    if (file.isDirectory())
    {
      for (final File f : file.listFiles())
      {
        final String newBasePatternStr =
             basePatternStr + file.getName() + "/";
        processFile(f, newBasePatternStr, patternList);
      }

      return;
    }


    final String fileName = file.getName();
    if (! fileName.endsWith(".class"))
    {
      final String completePatternStr = basePatternStr + file.getName() + "\\E";
      patternList.add(completePatternStr);
    }
  }
}
