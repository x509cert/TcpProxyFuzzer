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

// this is called multiple times, usually per block of data
// TODO: Add a Modern C++ version that accepts std::vector<uchar*>
bool Fuzz(_Inout_updates_bytes_(*pLen)	char* pBuf,
	_Inout_						unsigned int* pLen,
	_In_							unsigned int fuzzaggr,
	_In_							unsigned int fuzz_type) {

	// on first call, load the naughty strings file, but only if fuzz_type is not 'b'
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

	// don't fuzz everything
	// check for nulls
	// check data is not too small to fuzz
	if (rng.generatePercent() > fuzzaggr 
		|| pBuf == nullptr 
		|| pLen == nullptr 
		|| *pLen < MIN_BUFF_LEN) {
		printf("Non");
		return false;
	}

	// convert the incoming buffer to a gsl::span
	// which allows for safer buffer manipulation
	const gsl::span<char> buff(pBuf, *pLen);

	// get a random range to fuzz, but make sure it's big enough
	size_t start{}, end{};
	do {
		start = rng.range(0, *pLen).generate();
		end = rng.range(0, *pLen).generate();
		if (start > end) {
			const size_t tmp = start;
			start = end;
			end = tmp;
		}
	} while (end - start < MIN_BUFF_LEN); //TODO - double check this won't loop forever!

	// if we need to leave the main fuzzing loop
	bool earlyExit = false;

	// How many loops through the fuzzer?
	// most of the time, 90%, keep it at one iteration
	const unsigned int iterations = rng.range(0, 10).generate() != 7
		? 1
		: rng.range(1, 10).generate();

	// This is where the work is done
	for (size_t i = 0; i < iterations; i++) {

		// when laying down random chars, skip every N-bytes
		// 70% of the time, skip 1
		const size_t skip = rng.range(0, 10).generate() < 7
			? 1
			: rng.range(1, 10).generate();
		
		// which mutation to use. 
		// The upper-range is updated automatically as new mutations are added
		const auto whichMutation = static_cast<FuzzMutation>(rng.range(0, static_cast<unsigned int>(FuzzMutation::Max)).generate());

		switch (whichMutation) {
			///////////////////////////////////////////////////////////
			// no mutation
			case FuzzMutation::None:
				printf("Non");
				break;

			///////////////////////////////////////////////////////////
			// set the range to a random byte
			case FuzzMutation::RndByteSingle:
			{
				printf("Byt");
				const char byte = rng.generateChar();
				for (size_t j = start; j < end; j += skip) {
					gsl::at(buff,j) = byte;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// write random bytes to the range
			case FuzzMutation::RndByteMultiple:
			{
				printf("Rnd");
				for (size_t j = start; j < end; j += skip) {
					gsl::at(buff,j) = rng.generateChar();
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// a variant of above
			case FuzzMutation::ChangeASCIIInt:
			{
				printf("Chg");
				for (size_t j = start; j < end; j += skip) {
					auto c = gsl::at(buff, j);
					switch (rng.range(0, 4).generate()) {
						case 0	: c++;	break;
						case 1	: c--;	break;
						case 2	: c/=2; break;
						default	: c*=2; break;
					}

					gsl::at(buff, j) = c;
				}
			}
			break;
			
			///////////////////////////////////////////////////////////
			// set upper bit
			case FuzzMutation::SetUpperBit:
			{
				printf("Sup");
				for (size_t j = start; j < end; j += skip) {
					gsl::at(buff, j) |= 0x80;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// reset upper bit
			case FuzzMutation::ResetUpperBit:
			{
				printf("Rup");
				for (size_t j = start; j < end; j += skip) {
					gsl::at(buff, j) &= 0x7F;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// set the first zero-byte found to non-zero
			case FuzzMutation::ZeroByteToNonZero:
			{
				printf("Zer");
				for (size_t j = start; j < end; j++) {
					if (gsl::at(buff, j) == 0) {
						gsl::at(buff, j) = rng.generateChar();
						break;
					}
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// insert interesting edge-case numbers, often 2^n +/- 1
			case FuzzMutation::InterestingNumber:
			{
				printf("Num");
				const int interestingNum[] 
					= { 0,1,7,8,9,15,16,17,31,32,
						33,63,64,65,127,128,129,191,192,193,
						223,224,225,239,240,241,247,248,249,253,
						254,255 };
				
				for (size_t j = start; j < end; j += skip) {
					const auto which = rng.range(0, _countof(interestingNum)).generate();
					auto ch = gsl::narrow<unsigned char>(gsl::at(interestingNum, which));
					gsl::at(buff, j) = ch;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// insert interesting characters
			case FuzzMutation::InterestingChar:
			{
				printf("Chr");
				for (size_t j = start; j < end; j += skip) {
					const auto which = rng.range(0, gsl::narrow<unsigned int>(interestingChar.length())).generate();
					gsl::at(buff, j) = gsl::at(interestingChar,which);
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// replace interesting characters with space
			case FuzzMutation::ReplaceInterestingChar:
			{
				printf("Rep");
				for (size_t j = start; j < end; j++) {
					auto ch = gsl::at(buff, j);
					if (interestingChar.find(ch) != std::string::npos) {
						gsl::at(buff, j) = ' ';

						// 50% chance to break out of the loop
						if(rng.range(0, 10).generate() >= 5)
							break;
					}
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// truncate
			case FuzzMutation::Truncate:
			{
				printf("Trn");
				*pLen = gsl::narrow<unsigned int>(end);
				earlyExit = true;
			}
			break;

			///////////////////////////////////////////////////////////
			// overlong UTF-8 encodings
			case FuzzMutation::OverlongUtf8: 
			{
				printf("Utf");
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
					gsl::at(buff, j) = overlong.at(j - start);
			}

			break;

			///////////////////////////////////////////////////////////
			// insert naughty words
			// but not if we're doing binary fuzzing
			case FuzzMutation::NaughtyWord:
			{
				if (fuzz_type != 'b' && !naughty.empty()) {
					printf("Nau");

					const std::string& nty =
						naughty.at(rng.range(0, gsl::narrow<unsigned int>(naughty.size())).generate());

					for (size_t j = start; j < start + nty.size() && j < end; j++) {
						gsl::at(buff, j) = nty.at(j - start);
					}
				}
			}

			break;

			///////////////////////////////////////////////////////////
			// insert random Unicode (encoded as UTF-8)
			case FuzzMutation::RndUnicode: 
			{
				printf("Uni");
				auto utf8char = getRandomUnicodeCharacter();
				for (unsigned char byte : utf8char) {
					for (size_t j = start; j < start + utf8char.length() && j < end; j++)
						gsl::at(buff, j) = byte;
				}
			}

			break;

			default:
				break;
		}

		// right now, this only happens on truncation because we need 
		// to re-calc buffer sizes and this is the safest way to do it
		if (earlyExit == true)
			break; 
	}

	return true;
}

// the below is a work in progress
bool Fuzz(std::vector<char>& buff, unsigned int fuzzaggr, unsigned int fuzz_type) {
	if (buff.empty())
		return false;

	char* pBuff = buff.data();
	unsigned int length = gsl::narrow_cast<unsigned int>(buff.size());

	const bool result = Fuzz(pBuff, &length, fuzzaggr, fuzz_type);

	if (length != buff.size())
		buff.resize(length);

	return result;
}
