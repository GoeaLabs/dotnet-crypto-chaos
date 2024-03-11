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

namespace GoeaLabs.Crypto.Chaos;

/// <summary>
/// <see cref="ChaosEngine"/> error codes.
/// </summary>
public enum ChaosErrorCode
{
    /// <summary>
    /// No error.
    /// </summary>
    None,
    
    /// <summary>
    /// Invalid kernel length.
    /// </summary>
    ErrKernel,
    
    /// <summary>
    /// Invalid number of rounds.
    /// </summary>
    ErrRounds,
    
    /// <summary>
    /// <see cref="ChaosLocale"/> overflows.
    /// </summary>
    ErrLocale,
    
    /// <summary>
    /// Invalid [min, max) interval.
    /// </summary>
    /// <remarks>
    /// Set when the interval doesn't contain
    /// at least 2 numbers to choose from.
    /// </remarks>
    ErrMinMax,
    
    /// <summary>
    /// Invalid <see cref="BigInteger"/>
    /// bit length.
    /// </summary>
    ErrBitLen
}