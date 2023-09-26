#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <memory.h>
#include <sal.h>
#include <memory>
#include <intrin.h>

constexpr size_t MIN_BUFF_LEN = 8;

unsigned int GetRand() {
	unsigned int rndVal;
	while (_rdrand32_step(&rndVal) == 0);  
	return rndVal;
}

bool Fuzz(_Inout_updates_bytes_(*pLen)	char* pBuf,
		  _Inout_						size_t* pLen,
		  _In_							int fuzzaggr) {

	// don't fuzz everything
	if ((GetRand() % 100) > fuzzaggr)
		return false;

	// check for nulls
	if (pBuf == nullptr || pLen == nullptr) {
		return false;
	}

	// if data is too small to fuzz, return false
	if (*pLen < MIN_BUFF_LEN) {
		return false;
	}

	// get a random range to fuzz
	size_t start = GetRand() % *pLen;
	size_t end = GetRand() % *pLen;
	if (start > end) {
		const size_t tmp = start;
		start = end;
		end = tmp;
	}

	// don't fuzz if the range is too small
	if (end - start <= MIN_BUFF_LEN / 2) {
		return false;
	}

	// how many loops through the fuzzer?
	// most of the, 10%, keep it at one iteration
	const unsigned int iterations = GetRand() % 10 == 7
		? 1
		: 1 + GetRand() % 10;

	for (unsigned int i = 0; i < iterations; i++) {

		const unsigned int skip = GetRand() % 10 > 7 ? 1 + GetRand() % 10 : 1;
		const unsigned int whichMutation = GetRand() % 8;
		unsigned int j = 0;

		printf("%d", whichMutation);

		switch (whichMutation) {
		// set the range to a random byte
		case 0:
		{
			const char byte = GetRand() % 256;
			for (j = start; j < end; j += skip) {
				pBuf[j] = byte;
			}
		}
		break;

		// write random bytes to the range
		case 1:
		{
			for (j = start; j < end; j += skip) {
				pBuf[j] = GetRand() % 256;
			}
		}
		break;

		// set upper bit
		case 2:
			for (j = start; j < end; j += skip) {
				pBuf[j] |= 0x80;
			}
			break;

			// reset upper bit
		case 3:
			for (j = start; j < end; j += skip) {
				pBuf[j] &= 0x7F;
			}
			break;

			// set the first zero-byte found to non-zero
		case 4:
		{
			for (j = start; j < end; j += skip) {
				if (pBuf[j] == 0) {
					pBuf[j] = GetRand() % 256;
					break;
				}
			}
		}
		break;

		// insert interesting numbers
		case 5:
		{
			const int interestingNum[] = { 0,1,7,8,9,15,16,17,31,32,33,63,64,65,127,128,129,191,192,193,223,224,225,239,240,241,247,248,249,253,254,255 };
			for (j = start; j < end; j += skip) {
				pBuf[j] = (char)interestingNum[GetRand() % _countof(interestingNum)];
			}
		}
		break;

		// interesting characters
		case 6:
		{
			const char interestingChar[] = { ':', ';', '<', '>', '\\', '/', '.' };
			for (j = start; j < end; j += skip) {
				pBuf[j] = interestingChar[GetRand() % _countof(interestingChar)];
			}
		}
		break;

		// truncate
		case 7:
			*pLen = end;
			break;

		default:
			break;
		}
	}

	return true;
}
