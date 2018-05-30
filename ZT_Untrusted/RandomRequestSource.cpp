/*
*    ZeroTrace: Oblivious Memory Primitives from Intel SGX 
*    Copyright (C) 2018  Sajin (sshsshy)
*
*    This program is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, version 3 of the License.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
 * RandomRequestSource.cpp
 *
 *  Created on: Mar 26, 2017
 *      Author: root
 */

#include <random>
#include "RandomRequestSource.hpp"

int* RandomRequestSource::GenerateRandomSequence(int length, int max_capacity) {
	int* requestsource = (int *) malloc( length * sizeof(int) );
	std::default_random_engine generator;
	std::uniform_int_distribution<int> distribution(0,max_capacity-1);
	int i,val;

	for(i=0;i<length;i++)
	{
		val = distribution(generator);
		requestsource[i] = val;
	}

	return requestsource;
}


