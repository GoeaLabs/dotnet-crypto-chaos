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
using System.Runtime.CompilerServices;

namespace GoeaLabs.Crypto.Chaos.Internal;

/// <summary>
/// RFC8439 ChaCha implementation.
/// </summary>
[SkipLocalsInit]
internal static class Rfc8439
{
    /// <summary>
    /// Number of ChaCha constants.
    /// </summary>
    private const int Nc = 4;

    /// <summary>
    /// Key length in <see cref="uint"/>(s).
    /// </summary>
    public const int Kl = 8;

    /// <summary>
    /// Locale length in <see cref="uint"/>(s).
    /// </summary>
    public const int Ll = 4;

    /// <summary>
    /// State length in <see cref="uint"/>(s).
    /// </summary>
    public const int Sl = 16;

    /// <summary>
    /// Default number of rounds.
    /// </summary>
    public const int Dr = 20;

    /// <summary>
    /// 1st ChaCha8439 constant.
    /// </summary>
    private const uint C1 = 0x61707865;

    /// <summary>
    /// 2nd ChaCha8439 constant.
    /// </summary>
    private const uint C2 = 0x3320646e;

    /// <summary>
    /// 3rd ChaCha8439 constant.
    /// </summary>
    private const uint C3 = 0x79622d32;

    /// <summary>
    /// 4th ChaCha8439 constant.
    /// </summary>
    private const uint C4 = 0x6b206574;

    /// <summary>
    /// RFC8439 ChaCha quarter round.
    /// </summary>
    /// <param name="s">ChaCha state.</param>
    /// <param name="a">1st state index.</param>
    /// <param name="b">2nd state index.</param>
    /// <param name="c">3rd state index.</param>
    /// <param name="d">4th state index.</param>
    public static void QuarterRound(Span<uint> s, int a, int b, int c, int d)
    {
        s[d] = BitOperations.RotateLeft(s[d] ^= unchecked(s[a] += s[b]), 16);
        s[b] = BitOperations.RotateLeft(s[b] ^= unchecked(s[c] += s[d]), 12);
        s[d] = BitOperations.RotateLeft(s[d] ^= unchecked(s[a] += s[b]), 8);
        s[b] = BitOperations.RotateLeft(s[b] ^= unchecked(s[c] += s[d]), 7);
    }

    /// <summary>
    /// RFC8439 ChaCha block function.
    /// </summary>
    /// <param name="s">State to operate on.</param>
    /// <remarks>
    /// This is what the RFC calls the 'block' function. We call this 'InnerBlock',
    /// because it is only an intermediary step and it does not actually produce
    /// the random output block.
    /// </remarks>
    private static void InnerBlock(Span<uint> s)
    {
        QuarterRound(s, 0, 4, 8, 12);
        QuarterRound(s, 1, 5, 9, 13);
        QuarterRound(s, 2, 6, 10, 14);
        QuarterRound(s, 3, 7, 11, 15);
        QuarterRound(s, 0, 5, 10, 15);
        QuarterRound(s, 1, 6, 11, 12);
        QuarterRound(s, 2, 7, 8, 13);
        QuarterRound(s, 3, 4, 9, 14);
    }

    /// <summary>
    /// RFC8439 ChaCha final output.
    /// </summary>
    /// <param name="output">16 <see cref="uint"/>(s) buffer.</param>
    /// <param name="kernel">8 <see cref="uint"/>(s) buffer.</param>
    /// <param name="locale">4 <see cref="uint"/>(s) buffer.</param>
    /// <param name="rounds">Number of rounds to apply.</param>
    /// <remarks>
    /// We call this 'OuterBlock', because this is what the user actually
    /// receives the random output block.
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// If <paramref name="kernel"/> length is not equal to <see cref="Kl"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// If <paramref name="rounds"/> is not greater than zero and even.
    /// </exception>
    public static void OuterBlock(
        Span<uint> output, ReadOnlySpan<uint> kernel, ReadOnlySpan<uint> locale, int rounds)
    {
        Span<uint> primary = stackalloc uint[Sl];

        primary[0] = C1;
        primary[1] = C2;
        primary[2] = C3;
        primary[3] = C4;

        var keyPart = primary.Slice(Nc, Kl);
        var locPart = primary.Slice(Nc + Kl, Ll);

        kernel.CopyTo(keyPart);
        locale.CopyTo(locPart);

        Span<uint> mutated = stackalloc uint[Sl];

        primary.CopyTo(mutated);

        for (uint i = 0; i < rounds / 2; i++)
            InnerBlock(mutated);

        for (var i = 0; i < Sl; i++)
            output[i] = unchecked(primary[i] + mutated[i]);
    }
}