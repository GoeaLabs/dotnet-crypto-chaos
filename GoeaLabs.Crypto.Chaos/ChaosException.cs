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

namespace GoeaLabs.Crypto.Chaos;

/// <summary>
/// Represents errors that occur during
/// <see cref="ChaosEngine"/> operations.
/// </summary>
public class ChaosException : Exception
{
    /// <summary>
    /// Error code.
    /// </summary>
    public ChaosErrorCode ErrorCode { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="ChaosException"/>
    /// with a <see cref="ChaosErrorCode"/> and optional message
    /// and inner exception.
    /// </summary>
    /// <param name="errCode">Error code.</param>
    /// <param name="message">Message.</param>
    /// <param name="innerEx">Inner exception.</param>
    public ChaosException(ChaosErrorCode errCode, string? message = null, Exception? innerEx = null) 
        : base(message, innerEx) { ErrorCode = errCode; }
}