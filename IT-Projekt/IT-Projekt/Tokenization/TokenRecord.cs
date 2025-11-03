using System;
using System.Collections.Generic;
using em.Tokenization.V1;

namespace IT_Projekt
{
    /// <summary>
    /// Repräsentiert einen gespeicherten Datensatz für ein Token.  
    /// Wird im <see cref="ITokenStore"/> abgelegt und dient sowohl
    /// zur Detokenisierung (Rückführung von Token → Klartext)
    /// als auch für Auditing-/Verwaltungszwecke.
    /// </summary>
    public sealed class TokenRecord
    {
        /// <summary>
        /// Der generierte Tokenwert (z. B. v1.r.... oder v1.f....).
        /// Dient als Schlüssel für die Detokenisierung.
        /// </summary>
        public string Token { get; set; }

        /// <summary>
        /// ID des Tenants (Mandant), für den dieser Token erzeugt wurde.
        /// </summary>
        public string TenantId { get; set; }

        /// <summary>
        /// Feldname, auf den sich dieser Token bezieht (z. B. "email", "credit_card").
        /// </summary>
        public string Field { get; set; }

        /// <summary>
        /// Der ursprüngliche Klartextwert.  
        /// Achtung: Wird nur gespeichert, wenn es sich um eine reversible Tokenisierung handelt.
        /// Bei nicht-reversiblen Verfahren (z. B. Hash/HMAC ohne Store) bleibt dieses Feld leer.
        /// </summary>
        public string Plaintext { get; set; }

        /// <summary>
        /// Typ des Tokens (Random, FPE, HMAC, Hash, …).
        /// </summary>
        public TokenType Type { get; set; }

        /// <summary>
        /// Schlüssel-ID (KeyId), mit der der Token erzeugt wurde.  
        /// Dient der Versionierung bei Key-Rotation.
        /// </summary>
        public string KeyId { get; set; }

        /// <summary>
        /// Datenklasse, die den Inhalt beschreibt (z. B. Email, Telefonnummer, Kreditkarte).
        /// Hilfreich für Validierungen und Maskierungen.
        /// </summary>
        public DataClass DataClass { get; set; }

        /// <summary>
        /// Zeitstempel (UTC), wann der Token erzeugt und gespeichert wurde.
        /// </summary>
        public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Zusätzliche Attribute (frei definierbar).  
        /// Kann z. B. Metadaten für Auditing oder Klassifizierung enthalten.
        /// </summary>
        public IReadOnlyDictionary<string, string> Attributes { get; set; } 
            = new Dictionary<string, string>();
    }
}
