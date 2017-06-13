// Spooky Hash
// A 128-bit noncryptographic hash, for checksums and table lookup
// By Bob Jenkins.  Public domain.
//   Oct 31 2010: published framework, disclaimer ShortHash isn't right
//   Nov 7 2010: disabled ShortHash
//   Oct 31 2011: replace End, ShortMix, ShortEnd, enable ShortHash again
//   April 10 2012: buffer overflow on platforms without unaligned reads
//   July 12 2012: was passing out variables in final to in/out in short
//   July 30 2012: I reintroduced the buffer overflow
//   August 5 2012: SpookyV2: d = should be d += in short hash, and remove extra mix from long hash

#include <memory.h>
//#include "SpookyV2.h"
#include "spooky.h"

#define ALLOW_UNALIGNED_READS 1

//
// short hash ... it could be used on any message, 
// but it's used by Spooky just for short messages.
//
void SpookyHashShort(
    const void *message,
    size_t length,
    uint64 *hash1,
    uint64 *hash2)
{
    uint64 buf[2*sc_numVars];
    union 
    { 
        const uint8 *p8; 
        uint32 *p32;
        uint64 *p64; 
        size_t i; 
    } u;

    u.p8 = (const uint8 *)message;
    
    if (!ALLOW_UNALIGNED_READS && (u.i & 0x7))
    {
        memcpy(buf, message, length);
        u.p64 = buf;
    }

    size_t remainder = length & (size_t)31; //length%32
    uint64 a=*hash1;
    uint64 b=*hash2;
    uint64 c=sc_const;
    uint64 d=sc_const;

    if (length > 15)
    {
        const uint64 *end = u.p64 + (length/32)*4;
        
        // handle all complete sets of 32 bytes
        for (; u.p64 < end; u.p64 += 4)
        {
            c += u.p64[0];
            d += u.p64[1];
            SpookyHashShortMix(&a,&b,&c,&d);
            a += u.p64[2];
            b += u.p64[3];
        }
        
        //Handle the case of 16+ remaining bytes.
        if (remainder >= 16)
        {
            c += u.p64[0];
            d += u.p64[1];
            SpookyHashShortMix(&a,&b,&c,&d);
            u.p64 += 2;
            remainder -= 16;
        }
    }
    
    // Handle the last 0..15 bytes, and its length
    d += ((uint64)length) << 56;
    switch (remainder)
    {
    case 15:
    d += ((uint64)u.p8[14]) << 48;
    case 14:
        d += ((uint64)u.p8[13]) << 40;
    case 13:
        d += ((uint64)u.p8[12]) << 32;
    case 12:
        d += u.p32[2];
        c += u.p64[0];
        break;
    case 11:
        d += ((uint64)u.p8[10]) << 16;
    case 10:
        d += ((uint64)u.p8[9]) << 8;
    case 9:
        d += (uint64)u.p8[8];
    case 8:
        c += u.p64[0];
        break;
    case 7:
        c += ((uint64)u.p8[6]) << 48;
    case 6:
        c += ((uint64)u.p8[5]) << 40;
    case 5:
        c += ((uint64)u.p8[4]) << 32;
    case 4:
        c += u.p32[0];
        break;
    case 3:
        c += ((uint64)u.p8[2]) << 16;
    case 2:
        c += ((uint64)u.p8[1]) << 8;
    case 1:
        c += (uint64)u.p8[0];
        break;
    case 0:
        c += sc_const;
        d += sc_const;
    }
    SpookyHashShortEnd(&a,&b,&c,&d);
    *hash1 = a;
    *hash2 = b;
}




// do the whole hash in one call
void SpookyHashHash128(
    const void *message, 
    size_t length, 
    uint64 *hash1, 
    uint64 *hash2)
{
    if (length < sc_bufSize)
    {
        SpookyHashShort(message, length, hash1, hash2);
        return;
    }

    uint64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11;
    uint64 buf[sc_numVars];
    uint64 *end;
    union 
    { 
        const uint8 *p8; 
        uint64 *p64; 
        size_t i; 
    } u;
    size_t remainder;
    
    h0=h3=h6=h9  = *hash1;
    h1=h4=h7=h10 = *hash2;
    h2=h5=h8=h11 = sc_const;
    
    u.p8 = (const uint8 *)message;
    end = u.p64 + (length/sc_blockSize)*sc_numVars;

    // handle all whole sc_blockSize blocks of bytes
    if (ALLOW_UNALIGNED_READS || ((u.i & 0x7) == 0))
    {
        while (u.p64 < end)
        { 
            SpookyHashMix(u.p64, &h0,&h1,&h2,&h3,&h4,&h5,&h6,&h7,&h8,&h9,&h10,&h11);
	    u.p64 += sc_numVars;
        }
    }
    else
    {
        while (u.p64 < end)
        {
            memcpy(buf, u.p64, sc_blockSize);
            SpookyHashMix(buf, &h0,&h1,&h2,&h3,&h4,&h5,&h6,&h7,&h8,&h9,&h10,&h11);
	    u.p64 += sc_numVars;
        }
    }

    // handle the last partial block of sc_blockSize bytes
    remainder = (length - ((const uint8 *)end-(const uint8 *)message));
    memcpy(buf, end, remainder);
    memset(((uint8 *)buf)+remainder, 0, sc_blockSize-remainder);
    ((uint8 *)buf)[sc_blockSize-1] = remainder;
    
    // do some final mixing 
    SpookyHashEnd(buf, &h0,&h1,&h2,&h3,&h4,&h5,&h6,&h7,&h8,&h9,&h10,&h11);
    *hash1 = h0;
    *hash2 = h1;
}

/* API */
void SpookyHash128(const void *key, size_t len, uint64 seed1, uint64 seed2, uint64 *hash1, uint64 *hash2) {
    // Initialize the hash outputs to the seed
    *hash1 = seed1;
    *hash2 = seed2;

    // Compute the hash
    SpookyHashHash128(key, len, hash1, hash2);
}

// init spooky state
void SpookyHashInit(uint64 seed1, uint64 seed2, spooky_state *state)
{
    state->m_length = 0;
    state->m_remainder = 0;
    state->m_state[0] = seed1;
    state->m_state[1] = seed2;
}


// add a message fragment to the state
void SpookyHashUpdate(const void *message, size_t length, spooky_state *state)
{
    uint64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11;
    size_t newLength = length + state->m_remainder;
    uint8  remainder;
    union 
    { 
        const uint8 *p8; 
        uint64 *p64; 
        size_t i; 
    } u;
    const uint64 *end;
    
    // Is this message fragment too short?  If it is, stuff it away.
    if (newLength < sc_bufSize)
    {
        memcpy(&((uint8 *)(state->m_data))[state->m_remainder], message, length);
        state->m_length += length;
        state->m_remainder = (uint8)newLength;
        return;
    }
    
    // init the variables
    if (state->m_length < sc_bufSize)
    {
        h0=h3=h6=h9  = state->m_state[0];
        h1=h4=h7=h10 = state->m_state[1];
        h2=h5=h8=h11 = sc_const;
    }
    else
    {
        h0 = state->m_state[0];
        h1 = state->m_state[1];
        h2 = state->m_state[2];
        h3 = state->m_state[3];
        h4 = state->m_state[4];
        h5 = state->m_state[5];
        h6 = state->m_state[6];
        h7 = state->m_state[7];
        h8 = state->m_state[8];
        h9 = state->m_state[9];
        h10 = state->m_state[10];
        h11 = state->m_state[11];
    }
    state->m_length += length;
    
    // if we've got anything stuffed away, use it now
    if (state->m_remainder)
    {
        uint8 prefix = sc_bufSize - state->m_remainder;
        memcpy(&(((uint8 *)(state->m_data))[state->m_remainder]), message, prefix);
        u.p64 = state->m_data;
        SpookyHashMix(u.p64, &h0,&h1,&h2,&h3,&h4,&h5,&h6,&h7,&h8,&h9,&h10,&h11);
        SpookyHashMix(&u.p64[sc_numVars], &h0,&h1,&h2,&h3,&h4,&h5,&h6,&h7,&h8,&h9,&h10,&h11);
        u.p8 = ((const uint8 *)message) + prefix;
        length -= prefix;
    }
    else
    {
        u.p8 = (const uint8 *)message;
    }
    
    // handle all whole blocks of sc_blockSize bytes
    end = u.p64 + (length/sc_blockSize)*sc_numVars;
    remainder = (uint8)(length-((const uint8 *)end-u.p8));
    if (ALLOW_UNALIGNED_READS || (u.i & 0x7) == 0)
    {
        while (u.p64 < end)
        { 
            SpookyHashMix(u.p64, &h0,&h1,&h2,&h3,&h4,&h5,&h6,&h7,&h8,&h9,&h10,&h11);
	    u.p64 += sc_numVars;
        }
    }
    else
    {
        while (u.p64 < end)
        { 
            memcpy(state->m_data, u.p8, sc_blockSize);
            SpookyHashMix(state->m_data, &h0,&h1,&h2,&h3,&h4,&h5,&h6,&h7,&h8,&h9,&h10,&h11);
	    u.p64 += sc_numVars;
        }
    }

    // stuff away the last few bytes
    state->m_remainder = remainder;
    memcpy(state->m_data, end, remainder);
    
    // stuff away the variables
    state->m_state[0] = h0;
    state->m_state[1] = h1;
    state->m_state[2] = h2;
    state->m_state[3] = h3;
    state->m_state[4] = h4;
    state->m_state[5] = h5;
    state->m_state[6] = h6;
    state->m_state[7] = h7;
    state->m_state[8] = h8;
    state->m_state[9] = h9;
    state->m_state[10] = h10;
    state->m_state[11] = h11;
}


// report the hash for the concatenation of all message fragments so far
void SpookyHashFinal(uint64 *hash1, uint64 *hash2, spooky_state *state)
{
    // init the variables
    if (state->m_length < sc_bufSize)
    {
        *hash1 = state->m_state[0];
        *hash2 = state->m_state[1];
        SpookyHashShort( state->m_data, state->m_length, hash1, hash2);
        return;
    }
    
    const uint64 *data = (const uint64 *)(state->m_data);
    uint8 remainder = state->m_remainder;
    
    uint64 h0 = state->m_state[0];
    uint64 h1 = state->m_state[1];
    uint64 h2 = state->m_state[2];
    uint64 h3 = state->m_state[3];
    uint64 h4 = state->m_state[4];
    uint64 h5 = state->m_state[5];
    uint64 h6 = state->m_state[6];
    uint64 h7 = state->m_state[7];
    uint64 h8 = state->m_state[8];
    uint64 h9 = state->m_state[9];
    uint64 h10 = state->m_state[10];
    uint64 h11 = state->m_state[11];

    if (remainder >= sc_blockSize)
    {
        // m_data can contain two blocks; handle any whole first block
        SpookyHashMix(data, &h0,&h1,&h2,&h3,&h4,&h5,&h6,&h7,&h8,&h9,&h10,&h11);
        data += sc_numVars;
        remainder -= sc_blockSize;
    }

    // mix in the last partial block, and the length mod sc_blockSize
    memset(&((uint8 *)data)[remainder], 0, (sc_blockSize-remainder));

    ((uint8 *)data)[sc_blockSize-1] = remainder;
    
    // do some final mixing
    SpookyHashEnd(data, &h0,&h1,&h2,&h3,&h4,&h5,&h6,&h7,&h8,&h9,&h10,&h11);

    *hash1 = h0;
    *hash2 = h1;
}

