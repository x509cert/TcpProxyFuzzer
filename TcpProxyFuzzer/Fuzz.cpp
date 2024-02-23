#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <sal.h>
#include <memory>
#include <cstdio>
#include <vector>
#include <iostream>
#include <fstream>
#include <string>
#include <locale>
#include <codecvt>
#include <vector>
#include <algorithm>
#include <iterator>  

#include "rand.h"
#include "gsl\narrow"

// Using Microsoft C++ Guidelines Support Library (GSL) 
// https://github.com/microsoft/GSL/tree/main 
// GSL's span() comes with bounds checking
// Read this for background on why this code use gsl::span() and not std::span()
// https://github.com/microsoft/GSL/blob/main/docs/headers.md#gslspan
#include "gsl\span" 

// all the possible fuzz mutation types
enum class FuzzMutation : uint32_t {
	None,
	RndByteSingle,
	RndByteMultiple,
	ChangeASCIIInt, 
	SetUpperBit,
	ResetUpperBit,
	ZeroByteToNonZero,
	InterestingNumber,
	InterestingChar,
	Truncate,
	Grow,
	OverlongUtf8,
	NaughtyWord,
	RndUnicode,
	ReplaceInterestingChar,
	Max
};

// not going to bother fuzzing a small block
constexpr size_t MIN_BUFF_LEN = 16;

// some globals
const std::string interestingChar{ "~!:;\\/,.%-_`$^&#@?+=|\n\r\t\a*<>()[]{}\'\b\v\"\f" };

std::vector<std::string> naughty{};
bool naughtyLoadAttempted = false;

std::vector<std::string> naughtyJson{};
bool naughtyJsonLoadAttempted = false;

std::vector<std::string> naughtyHtml{};
bool naughtyHtmlLoadAttempted = false;

std::vector<std::string> naughtyXml{};
bool naughtyXmlLoadAttempted = false;

RandomNumberGenerator rng{};

#pragma warning(push)
#pragma warning(disable: 4996) // UTF8 encoding is deprecated, need to fix
// function that generates a random Unicode character
std::string getRandomUnicodeCharacter() {

	auto codePoint = rng.range(0x0000,0xFFFF).generate();

	// Avoid surrogate pair range, but recursively generate again if in surrogate pair range
	if (codePoint >= 0xD800 && codePoint <= 0xDFFF) 
		return getRandomUnicodeCharacter(); 

	std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
	return converter.to_bytes(std::wstring(1, gsl::narrow<wchar_t>(codePoint)));
}
#pragma warning(pop)

// Load a file of naughty strings
static void LoadNaughtyFile(std::string filename, std::vector<std::string>& words) {
	std::cout << "\nLoading " << filename << "\n";
	std::ifstream inputFile(filename, std::ios::in | std::ios::binary);
	if (inputFile.is_open()) {
		std::string line;
		while (std::getline(inputFile, line)) {
			// Check if the line is non-empty and does not start with #
			if (!line.empty() && line.at(0) != '#') {
				words.push_back(line);
			}
		}
	}
}

// This is called multiple times, usually per block of data
bool Fuzz(std::vector<char>& buffer, unsigned int fuzzaggr, unsigned int fuzz_type) {

	// don't fuzz everything
	// check data is not too small to fuzz
	auto bufflen = buffer.size();
	if (bufflen < MIN_BUFF_LEN || rng.generatePercent() > fuzzaggr) {
		fprintf(stderr, "Nnn");
		return false;
	}

	// On first call, load the naughty strings file, but only if fuzz_type is not 'b'
	// the 'attempted' flag is to prevent trying to load the file
	// if the file does not exist or there's a load error
	if (fuzz_type != 'b' && naughty.empty() && !naughtyLoadAttempted) {
		naughtyLoadAttempted = true;
		LoadNaughtyFile("naughty.txt", naughty);
	}

	// XML Naughty Strings
	if ((fuzz_type == 't' || fuzz_type == 'x') && naughtyXml.empty() && !naughtyXmlLoadAttempted) {
		naughtyXmlLoadAttempted = true;
		LoadNaughtyFile("naughtyXml.txt", naughtyXml);
	}

	// HTML Naughty Strings
	if ((fuzz_type == 't'|| fuzz_type == 'h') && naughtyHtml.empty() && !naughtyHtmlLoadAttempted) {
		naughtyHtmlLoadAttempted = true;
		LoadNaughtyFile("naughtyHtml.txt", naughtyHtml);
	}

	// JSON Naughty Strings
	if ((fuzz_type == 't' || fuzz_type == 'j') && naughtyJson.empty() && !naughtyJsonLoadAttempted) {
		naughtyJsonLoadAttempted = true;
		LoadNaughtyFile("naughtyJson.txt", naughtyJson);
	}

	// get a random range to fuzz, but make sure it's big enough
	size_t start{}, end{};
	do {
		start = rng.range(0, gsl::narrow_cast<unsigned int>(bufflen)).generate();
		end = rng.range(0, gsl::narrow_cast<unsigned int>(bufflen)).generate();
		if (start > end) {
			const size_t tmp = start;
			start = end;
			end = tmp;
		}
	} while (end - start < MIN_BUFF_LEN); //TODO - double check this won't loop forever!

	// if we need to leave the main fuzzing loop
	bool earlyExit = false;

	// How many loops through the fuzzer?
	const auto iterations = gsl::narrow_cast<unsigned int>(rng.generateNormal(6.5, 2.0, 1, 12));

	// This is where the work is done
	for (size_t i = 0; i < iterations; i++) {

		// when laying down random chars, skip every N-bytes
		// 70% of the time, skip 1-byte at a time
		const size_t skip = rng.range(0, 10).generate() < 7
			? 1
			: rng.range(1, 10).generate();
		
		// which mutation to use. 
		// The upper-range is updated automatically as new mutations are added
		const auto whichMutation 
			= static_cast<FuzzMutation>(rng.range(0, static_cast<unsigned int>(FuzzMutation::Max)).generate());

		switch (whichMutation) {
			///////////////////////////////////////////////////////////
			// no mutation
			case FuzzMutation::None:
				fprintf(stderr,"Non");
				break;

			///////////////////////////////////////////////////////////
			// set the range to a random byte
			case FuzzMutation::RndByteSingle:
			{
				fprintf(stderr, "Byt");
				const char byte = rng.generateChar();
				for (size_t j = start; j < end; j += skip) {
					buffer.at(j) = byte;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// write random bytes to the range
			case FuzzMutation::RndByteMultiple:
			{
				fprintf(stderr, "Rnd");
				for (size_t j = start; j < end; j += skip) {
					buffer.at(j) = rng.generateChar();
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// a variant of above
			case FuzzMutation::ChangeASCIIInt:
			{
				fprintf(stderr,"Chg");
				for (size_t j = start; j < end; j += skip) {
					auto c = buffer.at(j);
					switch (rng.range(0, 4).generate()) {
						case 0	: c++;	break;
						case 1	: c--;	break;
						case 2	: c/=2; break;
						default	: c*=2; break;
					}

					buffer.at(j) = c;
				}
			}
			break;
			
			///////////////////////////////////////////////////////////
			// set upper bit
			case FuzzMutation::SetUpperBit:
			{
				fprintf(stderr,"Sup");
				for (size_t j = start; j < end; j += skip) {
					buffer.at(j) |= 0x80;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// reset upper bit
			case FuzzMutation::ResetUpperBit:
			{
				fprintf(stderr,"Rup");
				for (size_t j = start; j < end; j += skip) {
					buffer.at(j) &= 0x7F;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// set the first zero-byte found to non-zero
			case FuzzMutation::ZeroByteToNonZero:
			{
				fprintf(stderr,"Zer");
				for (size_t j = start; j < end; j++) {
					if (buffer.at(j) == 0) {
						buffer.at(j) = rng.generateChar();
						break;
					}
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// insert interesting edge-case numbers, often 2^n +/- 1
			case FuzzMutation::InterestingNumber:
			{
				fprintf(stderr,"Num");
				const int interestingNum[] 
					= { 0,1,2,3,4,5,7,8,9,15,16,17,31,32,
						33,63,64,65,127,128,129,191,192,193,
						223,224,225,239,240,241,247,248,249,253,
						254,255 };
				
				for (size_t j = start; j < end; j += skip) {
					const auto which = rng.range(0, _countof(interestingNum)).generate();
					auto ch = gsl::narrow<unsigned char>(gsl::at(interestingNum, which));
					buffer.at(j) = ch;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// insert interesting characters
			case FuzzMutation::InterestingChar:
			{
				fprintf(stderr,"Chr");
				for (size_t j = start; j < end; j += skip) {
					const auto which = rng.range(0, gsl::narrow<unsigned int>(interestingChar.length())).generate();
					buffer.at(j) = gsl::at(interestingChar,which);
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// replace interesting characters with space
			case FuzzMutation::ReplaceInterestingChar:
			{
				fprintf(stderr,"Rep");
				for (size_t j = start; j < end; j++) {
					auto ch = buffer.at(j);
					if (interestingChar.find(ch) != std::string::npos) {
						buffer.at(j) = rng.generateChar();

						// 50% chance to break out of the loop and not tweak all characters
						if(rng.range(0, 10).generate() >= 5)
							break;
					}
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// truncate the buffer
			case FuzzMutation::Truncate:
			{
				fprintf(stderr,"Trn");
				bufflen = gsl::narrow<unsigned int>(end);
				buffer.resize(bufflen);
				earlyExit = true;
			}
			break;

			///////////////////////////////////////////////////////////
			// grow the buffer
			case FuzzMutation::Grow:
			{
				fprintf(stderr,"Gro");

				// take the midpoint of the start and end, 
				// and determine how much to grow the buffer
				const size_t mid = (end - start) / 2;
				const size_t fillsize = rng.range(4, 128).generate();

				// this vector will contain the insertion string, and is set to all-nulls
				std::vector<char> insert(fillsize);

				switch (fuzz_type) {
						
					case 'j': 
					{
						const auto len = gsl::narrow_cast<unsigned int>(naughtyJson.size());
						if (len) {
							std::string data = naughtyJson.at(rng.range(0, len).generate());
							auto replace_size = std::min(data.length(), fillsize);
							std::copy(data.begin(), data.begin() + replace_size, insert.begin());
						}
					}
					break;

					case 'x': 
					{
						const auto len = gsl::narrow_cast<unsigned int>(naughtyXml.size());
						if (len) {
							std::string data = naughtyXml.at(rng.range(0, len).generate());
							auto replace_size = std::min(data.length(), fillsize);
							std::copy(data.begin(), data.begin() + replace_size, insert.begin());
						}
					}
					break;

					case 'h': 
					{
						const auto len = gsl::narrow_cast<unsigned int>(naughtyHtml.size());
						if (len) {
							std::string data = naughtyHtml.at(rng.range(0, len).generate());
							auto replace_size = std::min(data.length(), fillsize);
							std::copy(data.begin(), data.begin() + replace_size, insert.begin());
						}
					}
					break;

					case 'b':
					default:
					{
						if (rng.range(0,10).generate() % 2) {
							for (char& c : insert)
								c = rng.generateChar();
						} else {
							auto r = rng.generateChar();
							for (char& c : insert)
								c = r;
						}

						break;
					}
				}

				buffer.insert(buffer.begin() + mid, insert.begin(), insert.end());
				earlyExit = true;
			}
			break;

			///////////////////////////////////////////////////////////
			// overlong UTF-8 encodings
			case FuzzMutation::OverlongUtf8: 
			{
				fprintf(stderr,"Utf");
				std::vector<unsigned char> overlong;
				const unsigned int choice = rng.range(0,3).generate();
				const char base_char = rng.generateChar();

				// just to make sure we don't run off the end of the buffer
				// max encoding len in 4, so this is a little more conservative
				// TODO: might use int overflow checks here instead
				if (end-start < MIN_BUFF_LEN/2)
					start = end - MIN_BUFF_LEN/2;

				switch (choice) {

					case 0:
						// 2-byte overlong encoding
						overlong.push_back(0b11000000 | (base_char >> 6));
						overlong.push_back(0b10000000 | (base_char & 0b00111111));
						break;

					case 1:
						// 3-byte overlong encoding
						overlong.push_back(0b11100000);
						overlong.push_back(0b10000000 | (base_char >> 6));
						overlong.push_back(0b10000000 | (base_char & 0b00111111));
						break;

					case 2:
						// 4-byte overlong encoding
						overlong.push_back(0b11110000);
						overlong.push_back(0b10000000 | (base_char >> 6));
						overlong.push_back(0b10000000 | (base_char & 0b00111111));
						overlong.push_back(0b10000000);
						break;

					default:
						break;
				}

				for (size_t j = start; j < start + overlong.size(); j++)
					buffer.at(j) = overlong.at(j - start);
			}

			break;

			///////////////////////////////////////////////////////////
			// insert naughty words
			// but not if we're doing binary fuzzing
			case FuzzMutation::NaughtyWord:
			{
				if (fuzz_type != 'b' && !naughty.empty()) {
					fprintf(stderr,"Nau");

					const std::string& nty =
						naughty.at(rng.range(0, gsl::narrow<unsigned int>(naughty.size())).generate());

					for (size_t j = start; j < start + nty.size() && j < end; j++) {
						buffer.at(j) = nty.at(j - start);
					}
				}
			}

			break;

			///////////////////////////////////////////////////////////
			// insert random Unicode (encoded as UTF-8)
			case FuzzMutation::RndUnicode: 
			{
				fprintf(stderr,"Uni");
				auto utf8char = getRandomUnicodeCharacter();
				for (unsigned char byte : utf8char) {
					for (size_t j = start; j < start + utf8char.length() && j < end; j++)
						buffer.at(j) = byte;
				}
			}

			break;

			default:
				fprintf(stderr,"???");
				break;
		}

		// right now, this only happens on buffer size change because we need 
		// to re-calc buffer sizes and this is the safest way to do it
		if (earlyExit == true)
			break; 
	}

	return true;
}
