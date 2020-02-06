#/bin/sh
#
#    ZeroTrace: Oblivious Memory Primitives from Intel SGX 
#    Copyright (C) 2018  Sajin (sshsshy)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, version 3 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

#N = Number of data blocks
N=10000
#no_of_req
no_of_req=10
#stash_size
key_size=4

#value_size is the equivalent to block_size for the ORAMs
value_size=1000

#<0/1 = InsidePRM/OutsidePRM>
PRM=1

#Obliviousness 0 = Read Oblivious, 1 = Full Oblivious (Read + Write Oblivious)
Obliv=0

log_file="log_LS"

exec_command="Sample_App/lsclient "$N" "$no_of_req" "$key_size" "$value_size" "$PRM" "$Obliv" "$log_file
echo $exec_command 
$exec_command

