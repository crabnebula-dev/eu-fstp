/**
 * TextSearch - Search for text patterns within extracted page text.
 *
 * Supports both literal string searches and regular expression patterns.
 * Returns match results with bounding box information.
 */

import type { BoundingBox, ExtractedChar, FindTextOptions, PageText, TextMatch } from "./types";
import { mergeBboxes } from "./types";

/**
 * Search for text in a page.
 *
 * @param pageText - The extracted page text
 * @param query - String or RegExp to search for
 * @param options - Search options
 * @returns Array of matches with positions
 */
export function searchPage(
  pageText: PageText,
  query: string | RegExp,
  options: FindTextOptions = {},
): TextMatch[] {
  const matches: TextMatch[] = [];

  // Flatten all characters from the page
  const allChars = flattenChars(pageText);

  // Build a mapping from plain text index to character index
  const textToCharMap = buildTextToCharMap(pageText, allChars);

  // Get the searchable text
  let searchText = pageText.text;

  // Handle case-insensitive search for string queries
  let effectiveQuery = query;

  if (typeof query === "string" && options.caseSensitive === false) {
    searchText = searchText.toLowerCase();
    effectiveQuery = query.toLowerCase();
  }

  // Find matches
  if (typeof effectiveQuery === "string") {
    findStringMatches(
      searchText,
      effectiveQuery,
      options,
      textToCharMap,
      allChars,
      pageText.pageIndex,
      matches,
    );
  } else {
    findRegexMatches(
      searchText,
      effectiveQuery,
      textToCharMap,
      allChars,
      pageText.pageIndex,
      matches,
    );
  }

  return matches;
}

/**
 * Flatten all characters from page text into a single array.
 */
function flattenChars(pageText: PageText): ExtractedChar[] {
  const chars: ExtractedChar[] = [];

  for (const line of pageText.lines) {
    for (const span of line.spans) {
      chars.push(...span.chars);
    }
  }

  return chars;
}

/**
 * Build a mapping from plain text character index to the index in allChars.
 * This accounts for newlines that are inserted between lines.
 */
function buildTextToCharMap(pageText: PageText, _allChars: ExtractedChar[]): Map<number, number> {
  const map = new Map<number, number>();
  let textIndex = 0;
  let charIndex = 0;

  for (let lineIdx = 0; lineIdx < pageText.lines.length; lineIdx++) {
    const line = pageText.lines[lineIdx];

    for (const span of line.spans) {
      for (let i = 0; i < span.chars.length; i++) {
        map.set(textIndex, charIndex);
        // Advance text index by character length (some chars may be multi-codepoint)
        textIndex += span.chars[i].char.length;
        charIndex++;
      }
    }

    // Account for the newline between lines (except after last line)
    if (lineIdx < pageText.lines.length - 1) {
      textIndex++; // For the \n
    }
  }

  return map;
}

/**
 * Find string matches and add to results.
 */
function findStringMatches(
  searchText: string,
  query: string,
  options: FindTextOptions,
  textToCharMap: Map<number, number>,
  allChars: ExtractedChar[],
  pageIndex: number,
  matches: TextMatch[],
): void {
  let startIndex = 0;

  while (true) {
    const foundIndex = searchText.indexOf(query, startIndex);

    if (foundIndex === -1) {
      break;
    }

    // Check whole word option
    if (options.wholeWord) {
      const before = foundIndex > 0 ? searchText[foundIndex - 1] : " ";
      const after =
        foundIndex + query.length < searchText.length ? searchText[foundIndex + query.length] : " ";

      if (!isWordBoundary(before) || !isWordBoundary(after)) {
        startIndex = foundIndex + 1;
        continue;
      }
    }

    // Get match info
    const match = buildMatch(foundIndex, query.length, textToCharMap, allChars, pageIndex, query);

    if (match) {
      matches.push(match);
    }

    startIndex = foundIndex + 1;
  }
}

/**
 * Find regex matches and add to results.
 */
function findRegexMatches(
  searchText: string,
  query: RegExp,
  textToCharMap: Map<number, number>,
  allChars: ExtractedChar[],
  pageIndex: number,
  matches: TextMatch[],
): void {
  // Ensure regex has global flag for findAll behavior
  const regex = query.global ? query : new RegExp(query.source, `${query.flags}g`);

  let match: RegExpExecArray | null = regex.exec(searchText);

  while (match !== null) {
    const matchText = match[0];
    const foundIndex = match.index;

    const textMatch = buildMatch(
      foundIndex,
      matchText.length,
      textToCharMap,
      allChars,
      pageIndex,
      matchText,
    );

    if (textMatch) {
      matches.push(textMatch);
    }

    // Prevent infinite loop on zero-length matches
    if (match[0].length === 0) {
      regex.lastIndex++;
    }

    match = regex.exec(searchText);
  }
}

/**
 * Build a TextMatch from a found index.
 */
function buildMatch(
  textIndex: number,
  length: number,
  textToCharMap: Map<number, number>,
  allChars: ExtractedChar[],
  pageIndex: number,
  matchText: string,
): TextMatch | null {
  // Find the character range for this match
  const startCharIndex = textToCharMap.get(textIndex);

  if (startCharIndex === undefined) {
    return null;
  }

  // Find the end character index
  // We need to count through the characters
  const charBoxes: BoundingBox[] = [];
  let currentTextIndex = textIndex;
  let currentCharIndex = startCharIndex;

  while (currentTextIndex < textIndex + length && currentCharIndex < allChars.length) {
    const char = allChars[currentCharIndex];
    charBoxes.push(char.bbox);
    currentTextIndex += char.char.length;
    currentCharIndex++;
  }

  if (charBoxes.length === 0) {
    return null;
  }

  return {
    text: matchText,
    bbox: mergeBboxes(charBoxes),
    pageIndex,
    charBoxes,
  };
}

/**
 * Check if a character is a word boundary (whitespace or punctuation).
 */
function isWordBoundary(char: string): boolean {
  return /[\s.,;:!?'"()[\]{}<>/\\|@#$%^&*+=~`-]/.test(char);
}

/**
 * Search across multiple pages.
 *
 * @param pages - Array of PageText to search
 * @param query - String or RegExp to search for
 * @param options - Search options
 * @returns Array of matches with positions
 */
export function searchPages(
  pages: PageText[],
  query: string | RegExp,
  options: FindTextOptions = {},
): TextMatch[] {
  const matches: TextMatch[] = [];
  const pagesToSearch = options.pages ?? pages.map((_, i) => i);

  for (const pageIndex of pagesToSearch) {
    if (pageIndex >= 0 && pageIndex < pages.length) {
      const pageMatches = searchPage(pages[pageIndex], query, options);
      matches.push(...pageMatches);
    }
  }

  return matches;
}
