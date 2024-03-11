using GoeaLabs.Bedrock.Extensions;
using GoeaLabs.Crypto.Chaos.Internal;

namespace GoeaLabs.Crypto.Chaos.Tests;

public static class ChaosTestVectors
{
    public static class QuarterRound
    {
        public const int A = 2;

        public const int B = 7;

        public const int C = 8;

        public const int D = 13;
        
        public static uint[] Test =>
        [
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
            0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
        ];

        public static uint[] Pass =>
        [
            0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
            0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320
        ];
    }
    
    public static class OuterBlock
    {
        /// <summary>
        /// RFC8439 ChaCha test key.
        /// </summary>
        public static readonly uint[] Kernel =
        [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
        ];

        /// <summary>
        /// RFC8439 ChaCha desired state at the end of 20 rounds,
        /// as <see cref="uint"/>(s).
        /// </summary>
        public static readonly uint[] Expect32 =
        [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
        ];

        /// <summary>
        /// RFC8439 ChaCha desired state at the end of 20 rounds,
        /// as <see cref="byte"/>(s).
        /// </summary>
        public static readonly byte[] Expect8 = new byte[ChaosEngine.PebbleLen];
        
        /// <summary>
        /// RFC8439 ChaCha desired state at the end of 20 rounds,
        /// as <see cref="ulong"/>(s).
        /// </summary>
        public static readonly ulong[] Expect64 = new ulong[ChaosEngine.PebbleLen64];

        /// <summary>
        /// RFC8439 ChaCha test counter and nonce.
        /// </summary>
        public static readonly uint[] Locale = [0x00000001, 0x09000000, 0x4a000000, 0x00000000];

        /// <summary>
        /// 64 bit counter.
        /// </summary>
        public static readonly ulong Pebble = Locale[0].Merge(Locale[1]);

        /// <summary>
        /// 64 bit nonce.
        /// </summary>
        public static readonly ulong Stream = Locale[2].Merge(Locale[3]);

        /// <summary>
        /// RFC8439 ChaCha rounds.
        /// </summary>
        public const int Rounds = Rfc8439.Dr;

        static OuterBlock()
        {
            Expect32.AsSpan().Split(Expect8);
            Expect32.AsSpan().Merge(Expect64);
        }
    }
}