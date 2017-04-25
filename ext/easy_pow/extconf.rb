require 'mkmf'
$CFLAGS += " -O3 -std=c11 -march=native -fopenmp" 

have_library("stdc++")
have_header('openssl/sha.h')
have_library('crypto')
have_library('gomp')
create_makefile("easy_pow/ext")  
