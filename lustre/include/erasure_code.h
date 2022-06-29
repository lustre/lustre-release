// SPDX-License-Identifier: BSD-2-Clause
/**********************************************************************
 * Copyright(c) 2011-2015 Intel Corporation All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *    Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  Neither the name of Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _ERASURE_CODE_H_
#define _ERASURE_CODE_H_

/**
 *  @file erasure_code.h
 *  @brief Interface to functions supporting erasure code encode and decode.
 *
 *  This file defines the interface to optimized functions used in erasure
 *  codes.  Encode and decode of erasures in GF(2^8) are made by calculating the
 *  dot product of the symbols (bytes in GF(2^8)) across a set of buffers and a
 *  set of coefficients.  Values for the coefficients are determined by the type
 *  of erasure code.  Using a general dot product means that any sequence of
 *  coefficients may be used including erasure codes based on random
 *  coefficients.
 *  Multiple versions of dot product are supplied to calculate 1-6 output
 *  vectors in one pass.
 *  Base GF multiply and divide functions can be sped up by defining
 *  GF_LARGE_TABLES at the expense of memory size.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize 32-byte constant array for GF(2^8) vector multiply
 *
 * Calculates array {C{00}, C{01}, C{02}, ... , C{0f} }, {C{00}, C{10},
 * C{20}, ... , C{f0} } as required by other fast vector multiply
 * functions.
 * @param c     Constant input.
 * @param gftbl Table output.
 */
void gf_vect_mul_init(unsigned char c, unsigned char *gftbl);

/**
 * @brief Initialize tables for fast Erasure Code encode and decode.
 *
 * Generates the expanded tables needed for fast encode or decode for erasure
 * codes on blocks of data.  32bytes is generated for each input coefficient.
 *
 * @param k      The number of vector sources or rows in the generator matrix
 *               for coding.
 * @param rows   The number of output vectors to concurrently encode/decode.
 * @param a      Pointer to sets of arrays of input coefficients used to encode
 *               or decode data.
 * @param gftbls Pointer to start of space for concatenated output tables
 *               generated from input coefficients.  Must be of size 32*k*rows.
 * @returns none
 */
void ec_init_tables(int k, int rows, unsigned char *a, unsigned char *gftbls);

/**
 * @brief Generate or decode erasure codes on blocks of data, runs appropriate
 * version.
 *
 * Given a list of source data blocks, generate one or multiple blocks of
 * encoded data as specified by a matrix of GF(2^8) coefficients. When given a
 * suitable set of coefficients, this function will perform the fast generation
 * or decoding of Reed-Solomon type erasure codes.
 *
 * This function determines what instruction sets are enabled and
 * selects the appropriate version at runtime.
 *
 * @param len    Length of each block of data (vector) of source or dest data.
 * @param k      The number of vector sources or rows in the generator matrix
 *		 for coding.
 * @param rows   The number of output vectors to concurrently encode/decode.
 * @param gftbls Pointer to array of input tables generated from coding
 *		  coefficients in ec_init_tables(). Must be of size 32*k*rows
 * @param data   Array of pointers to source input buffers.
 * @param coding Array of pointers to coded output buffers.
 * @returns none
 */
void ec_encode_data(int len, int k, int rows, unsigned char *gftbls,
		    unsigned char **data, unsigned char **coding);

/**
 * @brief Generate a Cauchy matrix of coefficients to be used for encoding.
 *
 * Cauchy matrix example of encoding coefficients where high portion of matrix
 * is identity matrix I and lower portion is constructed as 1/(i + j) | i != j,
 * i:{0,k-1} j:{k,m-1}.  Any sub-matrix of a Cauchy matrix should be invertable.
 *
 * @param a  [m x k] array to hold coefficients
 * @param m  number of rows in matrix corresponding to srcs + parity.
 * @param k  number of columns in matrix corresponding to srcs.
 * @returns  none
 */
void gf_gen_cauchy1_matrix(unsigned char *a, int m, int k);

/**
 * @brief Invert a matrix in GF(2^8)
 *
 * Attempts to construct an n x n inverse of the input matrix. Returns non-zero
 * if singular. Will always destroy input matrix in process.
 *
 * @param in  input matrix, destroyed by invert process
 * @param out output matrix such that [in] x [out] = [I] - identity matrix
 * @param n   size of matrix [nxn]
 * @returns 0 successful, other fail on singular input matrix
 */
int gf_invert_matrix(unsigned char *in, unsigned char *out, const int n);

/*************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* _ERASURE_CODE_H_ */
