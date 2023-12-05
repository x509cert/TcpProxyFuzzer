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
	SetUpperBit,
	ResetUpperBit,
	ZeroByteToNonZero,
	InterestingNumber,
	InterestingChar,
	Truncate,
	OverlongUtf8,
	NaughtyWord,
	RndUnicode,
	Max
};

// not going to bother fuzzing a small block
constexpr size_t MIN_BUFF_LEN = 16;

// some globals
std::vector<std::string> naughtyStrings{};
bool naughtyStringsLoadAttempted = false;
RandomNumberGenerator rng{};

#pragma warning(push)
#pragma warning(disable: 4996) // UTF8 encoding is deprecated, need to fix
// function that generates a random Unicode character
std::string getRandomUnicodeCharacter() {

	auto codePoint = rng.setRange(0x0000,0xFFFF).generate();

	// Avoid surrogate pair range, but recursively generate again if in surrogate pair range
	if (codePoint >= 0xD800 && codePoint <= 0xDFFF) 
		return getRandomUnicodeCharacter(); 

	std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
	return converter.to_bytes(std::wstring(1, gsl::narrow<wchar_t>(codePoint)));
}
#pragma warning(pop)

// this is called multiple times, usually per block of data
// TODO: Add a Modern C++ version that accepts vec<uchar*>
bool Fuzz(_Inout_updates_bytes_(*pLen)	char* pBuf,
		  _Inout_						unsigned int* pLen,
		  _In_							unsigned int fuzzaggr) {

	// on first call, load the naughty strings file
	// the 'attempted' flag is to prevent trying to load the file
	// if the file does not exist or there's a load error
	if (naughtyStrings.empty() && !naughtyStringsLoadAttempted) {
		naughtyStringsLoadAttempted = true;

		std::ifstream inputFile("naughty.txt", std::ios::in | std::ios::binary);
		if (inputFile.is_open()) {
			std::string line;
			while (std::getline(inputFile, line)) {
				// Check if the line is non-empty and does not start with #
				if (!line.empty() && line.at(0) != '#') {
					naughtyStrings.push_back(line);
				}
			}
		}

		inputFile.close();
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
		start = rng.setRange(0, *pLen).generate();
		end = rng.setRange(0, *pLen).generate();
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
	const unsigned int iterations = rng.setRange(0, 10).generate() != 7
		? 1
		: rng.setRange(1, 10).generate();

	// This is where the work is done
	for (size_t i = 0; i < iterations; i++) {

		// when laying down random chars, skip every N-bytes
		// 70% of the time, skip 1
		const size_t skip = rng.setRange(0, 10).generate() < 7
			? 1
			: rng.setRange(1, 10).generate();
		
		// which mutation to use. 
		// Update the upper-range as new mutations are added
		const auto whichMutation = static_cast<FuzzMutation>(rng.setRange(0, static_cast<unsigned int>(FuzzMutation::Max)).generate());

		switch (whichMutation) {
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
				for (size_t j = start; j < end; j += skip) {
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
					const auto which = rng.setRange(0, _countof(interestingNum)).generate();
					auto ch = gsl::narrow<unsigned char>(gsl::at(interestingNum, which));
					gsl::at(buff, j) = ch;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// interesting characters
			case FuzzMutation::InterestingChar:
			{
				printf("Chr");
				const std::string interestingChar{ "~!:;\\/,.%-_`$^&#@?+=|\n\r\t*<>()[]{}" };
				for (size_t j = start; j < end; j += skip) {
					const auto which = rng.setRange(0, gsl::narrow<unsigned int>(interestingChar.length())).generate();
					gsl::at(buff, j) = gsl::at(interestingChar,which);
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
				const unsigned int choice = rng.setRange(0,3).generate();
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
			case FuzzMutation::NaughtyWord:
			{
				if (!naughtyStrings.empty()) {
					printf("Nau");

					const std::string& naughty =
						naughtyStrings.at(rng.setRange(0, gsl::narrow<unsigned int>(naughtyStrings.size())).generate());

					for (size_t j = start; j < start + naughty.size() && j < end; j++) {
						gsl::at(buff, j) = naughty.at(j - start);
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
