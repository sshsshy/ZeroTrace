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

#ifndef __ZT_CONFIG__ 
 
  //BACKEND choices 0 = Memory, 1 = HDD
  #define BACKEND 0

  // The PRM memory limit for Position Map of a ZeroTrace ORAM Instance in bytes.
  // (The recursion levels of the ORAM is paramterized by this value)
  #define MEM_POSMAP_LIMIT 1024 * 1024


  // If turned on, the client (TestCorrectness) will have a detailed microbenchmark
  // of time taken in each of part of the ORAM Access operation  
  #define DETAILED_MICROBENCHMARKER 1

  #define REVERSE_LEXICOGRAPHIC_EVICTION 1

  #define __ZT_CONFIG__ 
#endif 
