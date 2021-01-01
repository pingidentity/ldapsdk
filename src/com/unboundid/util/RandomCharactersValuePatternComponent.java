/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import java.text.ParseException;
import java.util.Random;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class defines a value pattern component whose values will be a specified
 * number of randomly selected characters from a given character set.  The
 * component should be generated from a pattern in the format
 * "random:length:characters", where length is the number of characters to
 * generate, and characters is the set of characters that may be included in the
 * generated values.
 */
final class RandomCharactersValuePatternComponent
      extends ValuePatternComponent
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1653000400888202919L;



  // The set of characters to include in the generated values.
  @NotNull private final char[] characterSet;

  // The number of characters to include in the generated values.
  private final int numCharacters;

  // The random number generator to use to seed the thread-local generators.
  @NotNull private final Random seedRandom;

  // The thread-local random number generators.
  @NotNull private final ThreadLocal<Random> threadLocalRandoms;



  /**
   * Creates a new instance of this value pattern component from the provided
   * information.
   *
   * @param  pattern     The pattern string that describes the contents of the
   *                     generated values.
   * @param  randomSeed  The value that will be used to seed the random number
   *                     generators.
   *
   * @throws  ParseException  If the provided pattern cannot be parsed to create
   *                          a valid timestamp value pattern component.
   */
  RandomCharactersValuePatternComponent(@NotNull final String pattern,
                                        final long randomSeed)
       throws ParseException
  {
    seedRandom = new Random(randomSeed);
    threadLocalRandoms = new ThreadLocal<>();

    // We know that the pattern starts with "random:", so we need to find
    // the position of the second colon that separates the length from the
    // character set.  If there is no second colon, then the rest of the string
    // will be the length and we will assume a character set containing all
    // lowercase ASCII letters.
    final int secondColonPos = pattern.indexOf(':', 7);
    final String numCharactersString;
    if (secondColonPos < 0)
    {
      characterSet = "abcdefghijklmnopqrstuvwxyz".toCharArray();
      numCharactersString = pattern.substring(7);
    }
    else
    {
      numCharactersString = pattern.substring(7, secondColonPos);

      final String characterSetString = pattern.substring(secondColonPos+1);
      characterSet = characterSetString.toCharArray();
    }

    try
    {
      numCharacters = Integer.parseInt(numCharactersString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ParseException(
           ERR_RANDOM_CHARS_VALUE_PATTERN_CANNOT_PARSE_LENGTH.get(pattern,
                numCharactersString),
           7);
    }

    if (numCharacters <= 0)
    {
      throw new ParseException(
           ERR_RANDOM_CHARS_VALUE_PATTERN_INVALID_LENGTH.get(pattern,
                numCharacters),
           7);
    }

    if (characterSet.length == 0)
    {
      throw new ParseException(
           ERR_RANDOM_CHARS_VALUE_PATTERN_EMPTY_CHAR_SET.get(pattern),
           secondColonPos+1);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  void append(@NotNull final StringBuilder buffer)
  {
    final Random random = getRandom();
    for (int i=0; i < numCharacters; i++)
    {
      buffer.append(characterSet[random.nextInt(characterSet.length)]);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  boolean supportsBackReference()
  {
    return true;
  }



  /**
   * Retrieves a random number generator for use by the current thread.
   *
   * @return  A random number generator for use by the current thread.
   */
  @NotNull()
  private Random getRandom()
  {
    Random random = threadLocalRandoms.get();
    if (random == null)
    {
      synchronized (seedRandom)
      {
        random = new Random(seedRandom.nextLong());
      }

      threadLocalRandoms.set(random);
    }

    return random;
  }
}
