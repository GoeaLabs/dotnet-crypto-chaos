/*
   Copyright 2022-2024, GoeaLabs

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

using System.Numerics;
using GoeaLabs.Bedrock.Extensions;
using System.Runtime.CompilerServices;
using GoeaLabs.Crypto.Chaos.Internal;

namespace GoeaLabs.Crypto.Chaos;

/// <summary>
/// A cryptographically secure deterministic
/// random number generator based on RFC8439
/// ChaCha.
/// </summary>
[SkipLocalsInit]
public static class ChaosEngine
{
    #region Internal constants
    
    /// <summary>
    /// Pebble length in <see cref="uint"/>(s).
    /// </summary>
    internal const int PebbleLen32 = 16;
    
    /// <summary>
    /// Pebble length in <see cref="ulong"/>(s).
    /// </summary>
    internal const int PebbleLen64 = 8;

    #endregion

    #region Private constants
    
    /// <summary>
    /// Invalid kernel length error message.
    /// </summary>
    private const string ErrKernel = "Invalid kernel length.";
    
    /// <summary>
    /// Invalid number of rounds error message.
    /// </summary>
    private const string ErrRounds = "Invalid number of rounds.";
    
    /// <summary>
    /// Invalid [min, max) interval error message.
    /// </summary>
    private const string ErrMinMax = "Invalid [min, max) interval.";

    /// <summary>
    /// Invalid BigInteger bit length error message.
    /// </summary>
    private const string ErrBitLen = "Invalid BigInteger bit length.";

    #endregion
    
    #region Public constants

    /// <summary>
    /// Kernel length in <see cref="uint"/>(s).
    /// </summary>
    // ReSharper disable once MemberCanBePrivate.Global
    public const int KernelLen = Rfc8439.Kl;

    /// <summary>
    /// Default number of rounds.
    /// </summary>
    public const int DefRounds = Rfc8439.Dr;

    /// <summary>
    /// Pebble length in <see cref="byte"/>(s).
    /// </summary>
    public const int PebbleLen = 64;
    
    /// <summary>
    /// Supported <see cref="BigInteger"/> bit length.
    /// </summary>
    // ReSharper disable once MemberCanBePrivate.Global
    public const int BigIntLen = 512;
    
    /// <summary>
    /// Smallest possible 512 bit signed <see cref="BigInteger"/>.
    /// </summary>
    public static readonly BigInteger BigIntMin = -BigInteger.One << (BigIntLen - 1);
    
    /// <summary>
    /// Largest possible 512 bit signed <see cref="BigInteger"/>.
    /// </summary>
    public static readonly BigInteger BigIntMax = (BigInteger.One << BigIntLen - 1) - 1;

    #endregion
    
    #region Internal methods
    
    /// <summary>
    /// Convenience wrapper outputting <see cref="uint"/>(s).
    /// </summary>
    /// <param name="output"><see cref="PebbleLen32"/> length buffer.</param>
    /// <param name="kernel"><see cref="KernelLen"/> length buffer.</param>
    /// <param name="rounds">Engine rounds.</param>
    /// <param name="locale">Engine locale.</param>
    /// <returns>A new locale to resume work from.</returns>
    /// <exception cref="ChaosException">
    /// If the <paramref name="locale"/> can no longer be advanced.
    /// </exception>
    internal static ChaosLocale OuterBlock(
        Span<uint> output, ReadOnlySpan<uint> kernel, int rounds, ChaosLocale locale)
    {
        Span<uint> rfcLoc = stackalloc uint[Rfc8439.Ll];

        locale.Pebble.Halve(out var high, out var low);

        rfcLoc[0] = high;
        rfcLoc[1] = low;

        locale.Stream.Halve(out high, out low);

        rfcLoc[2] = high;
        rfcLoc[3] = low;

        Rfc8439.OuterBlock(output, kernel, rfcLoc, rounds);
        
        return locale.Skip(1);
    }

    /// <summary>
    /// Convenience wrapper outputting <see cref="byte"/>(s).
    /// </summary>
    /// <param name="output"><see cref="PebbleLen"/> length buffer.</param>
    /// <param name="kernel"><see cref="KernelLen"/> length buffer.</param>
    /// <param name="rounds">Engine rounds.</param>
    /// <param name="locale">Engine locale.</param>
    /// <returns>A new locale to resume work from.</returns>
    /// <exception cref="ChaosException">
    /// If the <paramref name="locale"/> can no longer be advanced.
    /// </exception>
    internal static ChaosLocale OuterBlock(
        Span<byte> output, ReadOnlySpan<uint> kernel, int rounds, ChaosLocale locale)
    {
        Span<uint> buffer = stackalloc uint[PebbleLen32];
        var newLocale = OuterBlock(buffer, kernel, rounds, locale);
        
        buffer.Split(output);

        return newLocale;
    }
    
    /// <summary>
    /// Convenience wrapper outputting <see cref="ulong"/>(s).
    /// </summary>
    /// <param name="output"><see cref="PebbleLen64"/> length buffer.</param>
    /// <param name="kernel"><see cref="KernelLen"/> length buffer.</param>
    /// <param name="rounds">Engine rounds.</param>
    /// <param name="locale">Engine locale.</param>
    /// <returns>A new locale to resume work from.</returns>
    /// <exception cref="ChaosException">
    /// If the <paramref name="locale"/> can no longer be advanced.
    /// </exception>
    internal static ChaosLocale OuterBlock(
        Span<ulong> output, ReadOnlySpan<uint> kernel, int rounds, ChaosLocale locale)
    {
        Span<uint> buffer = stackalloc uint[PebbleLen32];
        var newLocale = OuterBlock(buffer, kernel, rounds, locale);

        buffer.Merge(output);

        return newLocale;
    }

    #endregion
    
    #region Public methods
    
    /// <summary>
    /// Writes <see cref="KernelLen"/> cryptographically secure
    /// <see cref="uint"/>(s).
    /// </summary>
    /// <param name="output">Buffer to write to.</param>
    /// <exception cref="ChaosException">
    /// If <paramref name="output"/> length is not equal to <see cref="KernelLen"/>.
    /// </exception>
    public static void NewKernel(Span<uint> output)
    {
        //Guard.HasSizeEqualTo(output, KernelLen);
        if (output.Length != KernelLen)
            throw new ChaosException(ChaosErrorCode.ErrKernel, ErrKernel);
        
        output.FillRandom();
    }

    /// <summary>
    /// Loads a buffer of with random <see cref="byte"/>(s).
    /// </summary>
    /// <remarks>
    /// If the number of rounds is at least <see cref="DefRounds"/>,
    /// the output is considered cryptographically secure in 2024.
    /// </remarks>
    /// <param name="output">Buffer to load-up.</param>
    /// <param name="kernel">Engine kernel.</param>
    /// <param name="rounds">Engine rounds.</param>
    /// <param name="locale">Engine locale.</param>
    /// <returns>A new locale to resume work from.</returns>
    /// <exception cref="ChaosException">
    /// If <paramref name="kernel"/> length is not equal to <see cref="KernelLen"/>.
    /// </exception>
    /// <exception cref="ChaosException">
    /// If <paramref name="rounds"/> is not greater than zero and even.
    /// </exception>
    /// <exception cref="ChaosException">
    /// If the <paramref name="locale"/> can no longer be advanced.
    /// </exception>
    public static ChaosLocale Load(
        Span<byte> output, 
        ReadOnlySpan<uint> kernel, 
        int rounds, 
        ChaosLocale locale)
    {
        if (kernel.Length != KernelLen)
            throw new ChaosException(ChaosErrorCode.ErrKernel, ErrKernel);
        
        if (rounds == 0 || rounds % 2 > 0)
            throw new ChaosException(ChaosErrorCode.ErrRounds, ErrRounds);
        
        if (output.IsEmpty)
            return locale;
        
        Span<byte> buffer = stackalloc byte[PebbleLen];

        var now = -1;
        var end = output.Length - 1;

        var newLoc = locale;
        
        while (now != end)
        {
            newLoc = OuterBlock(buffer, kernel, rounds, newLoc);
            
            foreach (var member in buffer)
            {
                output[++now] = member;
                
                if (now == end) break;
            }
        }

        return newLoc;
    }

    /// <summary>
    /// Loads a buffer of with cryptographically
    /// secure random <see cref="byte"/>(s).
    /// </summary>
    /// <param name="output">Buffer to load-up.</param>
    public static void Load(Span<byte> output)
    {
        Span<uint> kernel = stackalloc uint[KernelLen];
        NewKernel(kernel);

        _ = Load(output, kernel, DefRounds, new ChaosLocale());
    }

    /// <summary>
    /// Loads a buffer with random <see cref="long"/>(s) in the interval
    /// [<paramref name="minVal"/>, <paramref name="maxVal"/>).
    /// </summary>
    /// <remarks>
    /// If the number of rounds is at least <see cref="DefRounds"/>,
    /// the output is considered cryptographically secure in 2024.
    /// </remarks>
    /// <param name="output">Buffer load-up.</param>
    /// <param name="minVal">Minimum inclusive.</param>
    /// <param name="maxVal">Maximum exclusive.</param>
    /// <param name="kernel">Engine kernel.</param>
    /// <param name="rounds">Engine rounds.</param>
    /// <param name="locale">Engine locale.</param>
    /// <returns>A new locale to resume work from.</returns>
    /// <exception cref="ChaosException">
    /// If <paramref name="kernel"/> length is not equal to <see cref="KernelLen"/>.
    /// </exception>
    /// <exception cref="ChaosException">
    /// If <paramref name="rounds"/> is not greater than zero and even.
    /// </exception>
    /// <exception cref="ChaosException">
    /// If the interval [<paramref name="minVal"/>, <paramref name="maxVal"/>)
    /// does not contain at least 2 numbers to choose from.
    /// </exception>
    /// <exception cref="ChaosException">
    /// If the <paramref name="locale"/> can no longer be advanced.
    /// </exception>
    public static ChaosLocale Load(
        Span<long> output, 
        long minVal, 
        long maxVal, 
        ReadOnlySpan<uint> kernel, 
        int rounds, 
        ChaosLocale locale)
    {
        if (kernel.Length != KernelLen)
            throw new ChaosException(ChaosErrorCode.ErrKernel, ErrKernel);
        
        if (rounds == 0 || rounds % 2 > 0)
            throw new ChaosException(ChaosErrorCode.ErrRounds, ErrRounds);
        
        if (minVal >= maxVal - 1)
            throw new ChaosException(ChaosErrorCode.ErrMinMax, ErrMinMax);
        
        if (output.IsEmpty)
            return locale;
        
        var range = (ulong)maxVal - (ulong)minVal - 1;
        
        var mask = range;
        for (var i = 1; i < sizeof(long); i *= 2)
            mask |= mask >> i;

        Span<ulong> buffer = stackalloc ulong[PebbleLen64];

        var now = -1;
        var end = output.Length - 1;

        var newLoc = locale;

        while (now != end)
        {
            newLoc = OuterBlock(buffer, kernel, rounds, newLoc);
            
            foreach (var member in buffer)
            {
                var result = mask & member;

                if (result > range) 
                    continue;
                
                output[++now] = (long)result + minVal;
                
                if (now == end) 
                    break;
            }
        }

        return newLoc;
    }

    /// <summary>
    /// Loads a buffer with cryptographically  secure random <see cref="long"/>(s)
    /// in the interval [<paramref name="minVal"/>, <paramref name="maxVal"/>).
    /// </summary>
    /// <param name="output">Buffer to load-up.</param>
    /// <param name="minVal">Minimum inclusive.</param>
    /// <param name="maxVal">Maximum exclusive.</param>
    /// <exception cref="ChaosException">
    /// If the interval [<paramref name="minVal"/>, <paramref name="maxVal"/>)
    /// does not contain at least 2 numbers to choose from.
    /// </exception>
    public static void Load(Span<long> output, long minVal, long maxVal)
    {
        Span<uint> kernel = stackalloc uint[KernelLen];
        NewKernel(kernel);

        _ = Load(output, minVal, maxVal, kernel, DefRounds, new ChaosLocale());
    }
    
    /// <summary>
    /// Loads a buffer with random <see cref="BigInteger"/>(s) in the
    /// interval [<paramref name="minVal"/>, <paramref name="maxVal"/>).
    /// </summary>
    /// <remarks>
    /// If the number of rounds is at least <see cref="DefRounds"/>,
    /// the output is considered cryptographically secure in 2024.
    /// </remarks>
    /// <param name="output">Buffer load-up.</param>
    /// <param name="minVal">Minimum inclusive.</param>
    /// <param name="maxVal">Maximum exclusive.</param>
    /// <param name="kernel">Engine kernel.</param>
    /// <param name="rounds">Engine rounds.</param>
    /// <param name="locale">Engine locale.</param>
    /// <returns>A new locale to resume work from.</returns>
    /// <exception cref="ChaosException">
    /// If <paramref name="kernel"/> length is not equal to <see cref="KernelLen"/>.
    /// </exception>
    /// <exception cref="ChaosException">
    /// If <paramref name="rounds"/> is not greater than zero and even.
    /// </exception>
    /// <exception cref="ChaosException">
    /// If either <paramref name="minVal"/> or <paramref name="maxVal"/> does not
    /// fit in <see cref="BigIntLen"/> bits.
    /// </exception>
    /// <exception cref="ChaosException">
    /// If the interval [<paramref name="minVal"/>, <paramref name="maxVal"/>) does
    /// not contain at least 2 numbers to choose from.
    /// </exception>
    /// <exception cref="ChaosException">
    /// If the <paramref name="locale"/> can no longer be advanced.
    /// </exception>
    public static ChaosLocale Load(
        Span<BigInteger> output, 
        BigInteger minVal, 
        BigInteger maxVal, 
        ReadOnlySpan<uint> kernel, 
        int rounds, 
        ChaosLocale locale)
    {        
        if (kernel.Length != KernelLen)
            throw new ChaosException(ChaosErrorCode.ErrKernel, ErrKernel);
        
        if (rounds == 0 || rounds % 2 > 0)
            throw new ChaosException(ChaosErrorCode.ErrRounds, ErrRounds);

        if (minVal < BigIntMin || minVal > BigIntMax ||
            maxVal < BigIntMin || maxVal > BigIntMax) 
            throw new ChaosException(ChaosErrorCode.ErrBitLen, ErrBitLen);
        
        if (minVal >= maxVal - 1)
            throw new ChaosException(ChaosErrorCode.ErrMinMax, ErrMinMax);
        
        var range = maxVal - minVal - BigInteger.One;
        
        if (output.IsEmpty)
            return locale;
        
        BigInteger mask512;
        
        if (range <= ulong.MaxValue)
        {
            var mask64 = (ulong)range;

            for (var i = 1; i < 64; i *= 2)
                mask64 |= mask64 >> i;

            mask512 = mask64;

            for (var i = 64; i < BigIntLen; i *= 2)
                mask512 |= mask512 >> i;
        }
        else
        {
            mask512 = range;

            for (var i = 1; i < BigIntLen; i *= 2)
                mask512 |= mask512 >> i;
        }
        
        Span<byte> buffer = stackalloc byte[PebbleLen];

        var newLoc = locale;
        
        for (var i = 0; i < output.Length; i++)
        {
            BigInteger result;
            
            while (true)
            {
                newLoc = OuterBlock(buffer, kernel, rounds, newLoc);
                
                result = mask512 & new BigInteger(buffer, false, true);

                if (result > range) 
                    continue;
            
                result += minVal;
                
                break;
            }

            output[i] = result;
        }

        return newLoc;
    }

    /// <summary>
    /// Loads a buffer with cryptographically secure random <see cref="BigInteger"/>(s)
    /// in the interval [<paramref name="minVal"/>, <paramref name="maxVal"/>).
    /// </summary>
    /// <param name="output">Buffer load-up.</param>
    /// <param name="minVal">Minimum inclusive.</param>
    /// <param name="maxVal">Maximum exclusive.</param>
    /// <exception cref="ChaosException">
    /// If either <paramref name="minVal"/> or <paramref name="maxVal"/> does not
    /// fit in <see cref="BigIntLen"/> bits.
    /// </exception>
    /// <exception cref="ChaosException">
    /// If the interval [<paramref name="minVal"/>, <paramref name="maxVal"/>) does
    /// not contain at least 2 numbers to choose from.
    /// </exception>
    public static void Load(Span<BigInteger> output, BigInteger minVal, BigInteger maxVal)
    {
        Span<uint> kernel = stackalloc uint[KernelLen];
        NewKernel(kernel);

        _ = Load(output, minVal, maxVal, kernel, DefRounds, new ChaosLocale());
    }
    
    #endregion
}