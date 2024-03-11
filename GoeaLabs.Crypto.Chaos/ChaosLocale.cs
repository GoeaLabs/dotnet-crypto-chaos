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
/// <see cref="ChaosEngine"/> coordinates.
/// </summary>
public readonly struct ChaosLocale
{
    /// <summary>
    /// Locale stream overflow error message.
    /// </summary>
    private const string ErrLocale = "Locale stream overflow.";
    
    /// <summary>
    /// Pebble index.
    /// </summary>
    public ulong Pebble { get; }
    
    /// <summary>
    /// Stream index.
    /// </summary>
    public ulong Stream { get; }

    /// <summary>
    /// Constructs a new locale instance.
    /// </summary>
    public ChaosLocale() : this(0, 0) { }

    /// <summary>
    /// Constructs a new <see cref="ChaosLocale"/> instance
    /// from the supplied <paramref name="pebble"/> and
    /// <paramref name="stream"/>.
    /// </summary>
    /// <param name="pebble">Pebble index.</param>
    /// <param name="stream">Stream index.</param>
    public ChaosLocale(ulong pebble, ulong stream)
    {
        Pebble = pebble;
        Stream = stream;
    }
    
    /// <summary>
    /// Skips the indicated number of pebbles, starting from
    /// the current pebble.
    /// </summary>
    /// <param name="pebbles">How many pebbles to skip.</param>
    /// <returns>A new locale.</returns>
    /// <exception cref="ChaosException">
    /// If the calculation leads to stream overflow.
    /// </exception>
    public ChaosLocale Skip(ulong pebbles)
    {
        if (pebbles == 0) 
            return this;
        
        var oldPebble = Pebble;
        var newPebble = unchecked(Pebble + pebbles);

        try
        {
            return newPebble < oldPebble
                ? new ChaosLocale(newPebble, checked(Stream + 1))
                : new ChaosLocale(newPebble, Stream);
        }
        catch (OverflowException e)
        {
            throw new ChaosException(ChaosErrorCode.ErrLocale, ErrLocale, e);
        }
    }
    
    /// <summary>
    /// Computes the locale the engine should resume work from provided
    /// the current locale is used to produce the indicated number of bytes.
    /// </summary>
    /// <param name="nBytes">Number of bytes to compute for.</param>
    /// <returns>A new locale.</returns>
    /// <exception cref="ChaosException">
    /// If the calculation leads to stream overflow.
    /// </exception>
    public ChaosLocale Mock(ulong nBytes)
    {
        if (nBytes == 0)
            return this;
    
        var divRem = Math.DivRem(nBytes, ChaosEngine.PebbleLen);
        var needed = divRem.Quotient;
        
        if (divRem.Quotient == 0 || divRem.Remainder > 0)
            needed++;

        try
        {
            return ulong.MaxValue - Pebble >= needed 
                ? new ChaosLocale(Pebble + needed, Stream) 
                : new ChaosLocale(unchecked(Pebble + needed), checked(Stream + 1));
        }
        catch (OverflowException e)
        {
            throw new ChaosException(ChaosErrorCode.ErrLocale, ErrLocale, e);
        }
    }

    /// <summary>
    /// Checks whether this locale has the same coordinates as
    /// another locale.
    /// </summary>
    /// <param name="that">Coordinates to compare with.</param>
    /// <returns></returns>
    public bool Same(ChaosLocale that) => Pebble == that.Pebble && Stream == that.Stream;
    
    /// <summary>
    /// Returns the pebble and stream
    /// formatted as (Pebble,Stream).
    /// </summary>
    public override string ToString()
    {
        return $"(pebble = {Pebble}, stream = {Stream})";
    }
}