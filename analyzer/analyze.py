#!/usr/bin/env python3

'''
Watch your iOS kernel heap live as you groom it.

This dirty script parses syslog output of kernel_hooks
and post-processes it to detect contiguous allocated/freed
address ranges and live prints to terminal.

2022 PARS Defense (parsdefense.com)
'''

import re
import collections
from time import sleep
import os
import sys
import math

GREEN = '\033[92m'
YELLOW= '\033[93m'
ENDC = '\033[0m'

# A dict representing whole memory we keep track of
# Fermat: {Mem_block.start:Mem_block}
memory = {}

# a contiguous chunk of memory
class Mem_block():

    alloced = bool()
    start = int()
    end = int()

    def __init__(self, alloced = True, start = None, end = None):
        self.alloced = alloced
        self.start = start
        self.end = end

# to track chunk size layout of a contiguous range
class Chunk_layout_tracker():

    # format [{size:count}, {0x10000, 3}, ...]
    stack = None

    # add a new chunk size to the stack
    def push(self, size):
        # first
        if self.stack is None:
            self.stack = [{size:1}]
        # same as last one
        elif size in self.stack[len(self.stack) - 1].keys():
            self.stack[len(self.stack) - 1][size] += 1
        # different than last one
        elif size not in self.stack[len(self.stack) - 1].keys():
            self.stack.append({size:1})

    # to print
    def get_layout_str(self):
        s = ''
        for i in self.stack:
            s += str(hex(list(i.keys())[0])) + '(' + str(list(i.values())[0]) + '), '
        return s[:-2] # remove trailing comma

    # reset
    def clear(self):
        self.stack = None

# record allocation
def alloc(addr, size):
    m = Mem_block(True, addr, addr + size)
    memory[addr] = m

# record freeing
def free(addr, size):
    if addr in memory:
        memory[addr].alloced = False
        memory[addr].end = addr + size


# pretty print size (https://stackoverflow.com/a/14822210)
def convert_size(size_bytes):
   if size_bytes == 0:
       return '0B'
   size_name = ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB')
   i = int(math.floor(math.log(size_bytes, 1024)))
   p = math.pow(1024, i)
   s = round(size_bytes / p, 2)
   return '%s %s' % (s, size_name[i])


# print whole memory in a pretty structured way
def print_memory():
    print('\x1b[2J\x1b[H',end='') # clr screen

    prev_key = None
    mem = collections.OrderedDict(sorted(memory.items())) # order chunks by address
    cont_mem = Mem_block() # contiguous memory area to print

    chunk_layout = Chunk_layout_tracker()

    total_allocs = 0
    total_frees = 0

    for k in mem:

        # save chunk size
        chunk_layout.push(mem[k].end - mem[k].start)

        # record stats
        if mem[k].alloced:
            total_allocs += mem[k].end - mem[k].start
        else:
            total_frees += mem[k].end - mem[k].start

        # set (first key)
        if prev_key is None:
            cont_mem.start = mem[k].start
            cont_mem.end = mem[k].end
            cont_mem.alloced = mem[k].alloced


        # current mem is centiguous to prev one; concat em and continue
        elif prev_key and mem[k].start == mem[prev_key].end and mem[k].alloced == mem[prev_key].alloced:
            cont_mem.end = mem[k].end

        # contiguity is over; print last contiguous memory area & reset
        else:
            if cont_mem.alloced:
                print(YELLOW, '[Alloc] ', end='')
            else:
                print(GREEN, ' [Free] ', end='')
            print('Start:', hex(cont_mem.start), 'End:', hex(cont_mem.end), 'Layout:', chunk_layout.get_layout_str(), ENDC)

            cont_mem.start = mem[k].start
            cont_mem.end = mem[k].end
            cont_mem.alloced = mem[k].alloced

            chunk_layout.clear()

        prev_key = k

    print('-'*78)
    print(' '*50 + 'Total allocs:', convert_size(total_allocs),'\n' + ' '*50 + 'Total frees: ', convert_size(total_frees))




# print usage λ0
if len(sys.argv) == 1:
    print('Usage', sys.argv[0], '<file>')
    exit()

# open file
name = sys.argv[1]
current = open(name, 'r')
curino = os.fstat(current.fileno()).st_ino
do_print = True
# super loop
while True:
    # read file if it's updated, then print
    if do_print:
        for line in current:
            line = line.rstrip() # remove extra \n
            # grep
            try:
                if re.search('kernel_memory_allocate', line):
                    addr = int(line.split('*addrp = ')[1][:18], 16)
                    size = int(line.split('size = ')[1][:18], 16)
                    if addr != 0: # skip if allocator returned NULL
                        alloc(addr, size)
                if re.search('kmem_free', line):
                    addr = int(line.split('*addr  = ')[1][:18], 16)
                    size = int(line.split('size = ')[1][:18], 16)
                    free(addr, size)
                '''
                add hooked allocator/free functions here like above
                '''
            except: pass
        # print
        print_memory()
        do_print = False

    # check inode change to detect updates https://stackoverflow.com/a/25632664
    try:
        if os.stat(name).st_ino != curino:
            new = open(name, 'r')
            current.close()
            current = new
            curino = os.fstat(current.fileno()).st_ino
            continue
        else: # don't ask why we needed to put this under 'else'
            do_print = True
    except IOError:
        pass

    # interval to check file for updates
    sleep(0.2)
