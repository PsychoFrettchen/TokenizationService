using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using em.Tokenization.V1;
using Grpc.Core;
using IT_Projekt.CryptoImpl;
using IT_Projekt.Provider;

namespace IT_Projekt
{
    /// <summary>
    /// gRPC-Implementierung des Tokenization-Dienstes.
    /// 
    /// Verantwortlichkeiten:
    /// <list type="bullet">
    ///   <item><description>Tokenisierung (Random/Hash/HMAC/FPE/Encrypted)</description></item>
    ///   <item><description>Detokenisierung (über Store oder FPE/Encryption)</description></item>
    ///   <item><description>Key-Rotation (Bestimmung aktiver KeyId je Tenant)</description></item>
    ///   <item><description>Streaming-Tokenisierung (ein Init, viele Items)</description></item>
    /// </list>
    /// Abhängigkeiten:
    /// <list type="bullet">
    ///   <item><description><see cref="IKeyProvider"/>: Liefert/verwaltet Schlüssel (z. B. Vault)</description></item>
    ///   <item><description><see cref="ITokenStore"/>: Persistiert reversible Token (z. B. RANDOM) für Detokenisierung</description></item>
    ///   <item><description><see cref="IFpeEngine"/>: Optionaler FPE-Algorithmus (FF1/FF3-1); kann <c>null</c> sein</description></item>
    /// </list>
    /// </summary>
    public sealed class TokenizationServiceImpl : TokenizationService.TokenizationServiceBase
    {
        private const int AesKeyLen = 32;

        private readonly IKeyProvider keys;
        private readonly ITokenStore store;
        private readonly IFpeEngine fpe;            // kann null sein → FPE-Operationen sind dann deaktiviert
        private readonly bool storeNonReversible;   // optional: HASH/HMAC zusätzlich im Store ablegen (Policy)

        /// <summary>
        /// Erstellt eine neue Service-Instanz.
        /// </summary>
        /// <param name="keys">Schlüssel-Provider (z. B. VaultKeyProvider)</param>
        /// <param name="store">Token-Store für reversible Token (z. B. VaultHttpTokenStore)</param>
        /// <param name="fpe">FPE-Engine (kann null sein, dann sind FPE-Aufrufe nicht erlaubt)</param>
        /// <param name="storeNonReversible">Wenn true, werden auch HASH/HMAC im Store abgelegt (Detokenisierung via Store möglich)</param>
        public TokenizationServiceImpl(IKeyProvider keys, ITokenStore store, IFpeEngine fpe, bool storeNonReversible = false)
        {
            this.keys = keys ?? throw new ArgumentNullException(nameof(keys));
            this.store = store ?? throw new ArgumentNullException(nameof(store));
            this.fpe = fpe;
            this.storeNonReversible = storeNonReversible;
        }

        // ----------------- Unary -----------------

        /// <summary>
        /// Führt die Tokenisierung für eine Liste von Feldern durch.
        /// </summary>
        /// <exception cref="RpcException">InvalidArgument bei fehlerhaften Anfragen</exception>
        public override Task<TokenizeResponse> Tokenize(TokenizeRequest request, ServerCallContext context)
        {
            if (request == null) throw new RpcException(new Status(StatusCode.InvalidArgument, "Request is null"));
            if (request.Items == null || request.Items.Count == 0)
                throw new RpcException(new Status(StatusCode.InvalidArgument, "No items to tokenize"));

            var resp = new TokenizeResponse
            {
                // Effektive KeyId einmal ermitteln und in Response mitgeben
                KeyId = EffectiveKeyId(request.Context, keys),
            };

            foreach (var fp in request.Items)
            {
                try
                {
                    var token = TokenizeOne(fp, request.TokenType, request.Context, resp.KeyId);
                    resp.Items.Add(new TokenizedField { Field = fp.Field ?? "", Token = token });

                    // Reversible Typen ggf. persistieren (RANDOM immer; HMAC/HASH je nach Policy)
                    if (ShouldPersist(request.TokenType))
                    {
                        store.Save(new TokenRecord
                        {
                            Token     = token,
                            TenantId  = request.Context?.TenantId ?? "",
                            Field     = fp.Field ?? "",
                            Plaintext = fp.Plaintext ?? "",
                            Type      = request.TokenType,
                            KeyId     = resp.KeyId ?? "",
                            DataClass = fp.DataClass,
                            Attributes = fp.Attributes
                        });
                    }
                }
                catch (Exception ex)
                {
                    // Fehler pro Feld sammeln, statt global abzubrechen
                    resp.Errors.Add(new FieldError
                    {
                        Field = fp?.Field ?? "",
                        Code = 50001,
                        Message = $"Tokenization failed: {ex.Message}"
                    });
                }
            }

            return Task.FromResult(resp);
        }

        /// <summary>
        /// Führt die Detokenisierung durch. 
        /// Greift zuerst auf den Token-Store zu; wenn dort nichts liegt, versucht der Dienst
        /// je nach Typ eine kryptografische Rückführung (FPE/Encrypted).
        /// </summary>
        public override Task<DetokenizeResponse> Detokenize(DetokenizeRequest request, ServerCallContext context)
        {
            if (request == null) throw new RpcException(new Status(StatusCode.InvalidArgument, "Request is null"));
            if (request.Items == null || request.Items.Count == 0)
                throw new RpcException(new Status(StatusCode.InvalidArgument, "No items to detokenize"));

            var resp = new DetokenizeResponse
            {
                KeyId = EffectiveKeyId(request.Context, keys),
            };

            foreach (var item in request.Items)
            {
                try
                {
                    if (TryDetokenizeOne(item, request.Context, resp.KeyId, out var plaintext))
                        resp.Items.Add(new DetokenizedField { Field = item.Field ?? "", Plaintext = plaintext ?? "" });
                    else
                        resp.Errors.Add(new FieldError { Field = item.Field ?? "", Code = 40404, Message = "Token not found or not reversible with current policy." });
                }
                catch (Exception ex)
                {
                    resp.Errors.Add(new FieldError { Field = item.Field ?? "", Code = 50002, Message = $"Detokenization failed: {ex.Message}" });
                }
            }

            return Task.FromResult(resp);
        }

        /// <summary>
        /// Validiert die Struktur eines Tokens und liefert (falls vorhanden) Metadaten aus dem Store (Feldname, DataClass, KeyId).
        /// </summary>
        public override Task<ValidateTokenResponse> ValidateToken(ValidateTokenRequest request, ServerCallContext context)
        {
            var v = new ValidateTokenResponse { Valid = false, TokenType = TokenType.Unspecified };

            if (TokenWire.TryParse(request?.Token, out var typeTag, out _, out _))
            {
                v.Valid = true;
                v.TokenType = ParseType(typeTag);
                // Standard-KeyId bestimmen; falls im Store vorhanden, überschreiben wir diese später
                v.KeyId = request?.Context?.KeyId ?? keys.GetActiveKeyId(request?.Context?.TenantId ?? "");

                if (store.TryGet(request.Token, out var rec))
                {
                    v.Field = rec.Field ?? "";
                    v.DataClass = rec.DataClass;
                    v.KeyId = rec.KeyId;
                }
            }

            return Task.FromResult(v);
        }

        /// <summary>
        /// Setzt optional eine neue aktive KeyId für den Tenant und liefert die (neue) aktive KeyId zurück.
        /// </summary>
        public override Task<RotateKeyResponse> RotateKey(RotateKeyRequest request, ServerCallContext context)
        {
            var tenant = request?.Context?.TenantId ?? "";
            if (!string.IsNullOrEmpty(request?.NewKeyId))
                keys.Rotate(tenant, request.NewKeyId);

            return Task.FromResult(new RotateKeyResponse { ActiveKeyId = keys.GetActiveKeyId(tenant) });
        }

        // --------------- Streaming ----------------

        /// <summary>
        /// Bidirektionales Streaming: 
        /// Erste Nachricht muss <see cref="StreamTokenizeInit"/> enthalten (Typ &amp; Context),
        /// danach beliebig viele Items; pro Item wird sofort ein Ergebnis zurückgeschrieben.
        /// </summary>
        public override async Task StreamTokenize(IAsyncStreamReader<StreamTokenizeIn> requestStream,
                                                  IServerStreamWriter<StreamTokenizeOut> responseStream,
                                                  ServerCallContext context)
        {
            bool initialized = false;
            TokenType tokenType = TokenType.Unspecified;
            Context ctx = null;
            string keyId = null;

            while (await requestStream.MoveNext().ConfigureAwait(false))
            {
                var msg = requestStream.Current;
                if (!initialized)
                {
                    if (msg?.Init == null)
                        throw new RpcException(new Status(StatusCode.InvalidArgument, "First message must be init."));

                    initialized = true;
                    tokenType = msg.Init.TokenType;
                    ctx = msg.Init.Context ?? new Context();
                    keyId = EffectiveKeyId(ctx, keys);
                    continue;
                }

                if (msg.Item == null) continue;

                try
                {
                    var tok = TokenizeOne(new FieldPayload
                    {
                        Field         = msg.Item.Field,
                        Plaintext     = msg.Item.Plaintext,
                        DataClass     = msg.Item.DataClass,
                        PreserveFormat= msg.Item.PreserveFormat,
                        FormatMode    = msg.Item.FormatMode,
                        FormatMask    = msg.Item.FormatMask,
                        Attributes    = { msg.Item.Attributes }
                    }, tokenType, ctx, keyId);

                    if (ShouldPersist(tokenType))
                    {
                        store.Save(new TokenRecord
                        {
                            Token     = tok,
                            TenantId  = ctx?.TenantId ?? "",
                            Field     = msg.Item.Field ?? "",
                            Plaintext = msg.Item.Plaintext ?? "",
                            Type      = tokenType,
                            KeyId     = keyId ?? "",
                            DataClass = msg.Item.DataClass,
                            Attributes= msg.Item.Attributes
                        });
                    }

                    await responseStream.WriteAsync(new StreamTokenizeOut
                    {
                        Item = new TokenizedField { Field = msg.Item.Field ?? "", Token = tok }
                    }).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    await responseStream.WriteAsync(new StreamTokenizeOut
                    {
                        Error = new FieldError { Field = msg.Item.Field ?? "", Code = 50011, Message = ex.Message }
                    }).ConfigureAwait(false);
                }
            }
        }

        // ------------------------------------------
        // ============ Core helpers =================
        // ------------------------------------------

        /// <summary>
        /// Ermittelt die effektiv zu verwendende KeyId:
        /// Falls im Context gesetzt → diese; sonst die aktive KeyId aus dem <see cref="IKeyProvider"/>.
        /// </summary>
        private static string EffectiveKeyId(Context ctx, IKeyProvider keys)
        {
            var tenant = ctx?.TenantId ?? "";
            return !string.IsNullOrEmpty(ctx?.KeyId) ? ctx.KeyId : keys.GetActiveKeyId(tenant);
        }

        /// <summary>
        /// Policy: Welche Token-Typen werden zusätzlich im Store abgelegt?
        /// </summary>
        private bool ShouldPersist(TokenType type)
        {
            switch (type)
            {
                case TokenType.Random: return true;                    // RANDOM ist nur so reversibel
                case TokenType.Hmac:
                case TokenType.Hash:  return storeNonReversible;      // optional je nach Policy
                case TokenType.Fpe:   return false;                    // reversibel via IFpeEngine
                case TokenType.Encrypted:
                default:              return false;
            }
        }

        /// <summary>
        /// Wandelt das Typ-Kürzel aus dem Token in das Protobuf-Enum um.
        /// </summary>
        private TokenType ParseType(string tag)
        {
            switch (tag)
            {
                case "r":  return TokenType.Random;
                case "f":  return TokenType.Fpe;
                case "hc": return TokenType.Hmac;
                case "hs": return TokenType.Hash;
                case "e":  return TokenType.Encrypted;
                default:   return TokenType.Unspecified;
            }
        }

        /// <summary>
        /// Leitet anhand von <see cref="FieldPayload.DataClass"/> eine sinnvolle Alphabet-Domäne ab
        /// (z. B. nur Ziffern für Kartennummern).
        /// </summary>
        private static string InferAlphabet(FieldPayload fp)
        {
            switch (fp.DataClass)
            {
                case DataClass.CreditCard:
                case DataClass.Iban:
                case DataClass.Phone:
                case DataClass.Ssn:
                case DataClass.PostalCode:
                case DataClass.Date:
                    return Alphabets.Digits;
                default:
                    return Alphabets.Alnum;
            }
        }

        /// <summary>
        /// Fallback: Alphabet anhand des Feldnamens ableiten (für Detokenize von FPE-Tokens ohne DataClass).
        /// </summary>
        private static string InferAlphabetFromField(string field)
        {
            if (string.IsNullOrEmpty(field)) return Alphabets.Alnum;
            var f = field.ToLowerInvariant();
            if (f.Contains("card") || f.Contains("iban") || f.Contains("phone") || f.Contains("ssn") || f.Contains("zip") || f.Contains("postal"))
                return Alphabets.Digits;
            return Alphabets.Alnum;
        }

        /// <summary>
        /// Tokenisiert genau ein Feld, inkl. Key-Derivation (HKDF) pro Feld (tenant/kid/field).
        /// </summary>
        private string TokenizeOne(FieldPayload fp, TokenType type, Context ctx, string keyId)
        {
            if (fp == null) throw new ArgumentNullException(nameof(fp));

            var tenant    = ctx?.TenantId ?? "";
            var masterKey = keys.GetKey(tenant, keyId);
            if (masterKey == null || masterKey.Length == 0)
                throw new InvalidOperationException("Key provider returned no key material");

            // Ableitung eines Feld-Schlüssels (HKDF) mit Kontextbindung
            var tweak   = ctx?.Tweak?.ToByteArray() ?? Array.Empty<byte>();
            var purpose = Encoding.UTF8.GetBytes(ctx?.Purpose ?? "");
            var info    = Encoding.UTF8.GetBytes($"ctx|tenant={tenant}|kid={keyId}|field={fp.Field}");
            var derived = Crypto.Hkdf(masterKey, tweak, info, AesKeyLen);

            switch (type)
            {
                case TokenType.Random:
                {
                    // Reversibel nur via Store (wird in Tokenize() gespeichert)
                    var payload = Crypto.Base64Url(Crypto.RandomBytes(16));
                    return TokenWire.Build("r", keyId, payload);
                }

                case TokenType.Hash:
                {
                    var hex   = Crypto.Sha256Hex(fp.Plaintext ?? "");
                    var token = TokenWire.Build("hs", keyId, hex);
                    return ApplyMaskedViewIfRequested(token, fp, derived);
                }

                case TokenType.Hmac:
                {
                    var hex   = Crypto.HmacSha256Hex(fp.Plaintext ?? "", derived);
                    var token = TokenWire.Build("hc", keyId, hex);
                    return ApplyMaskedViewIfRequested(token, fp, derived);
                }

                case TokenType.Fpe:
                {
                    if (fpe == null)
                        throw new RpcException(new Status(StatusCode.FailedPrecondition, "FPE not configured. Provide an IFpeEngine."));

                    var alphabet = InferAlphabet(fp);
                    var cipher   = fpe.Encrypt(fp.Plaintext ?? "", derived, tweak, alphabet);

                    // Für reine Zifferndomäne bevorzugt als Ziffern einbetten, sonst als Base64Url
                    var payload = alphabet == Alphabets.Digits && cipher.All(char.IsDigit)
                        ? cipher
                        : Crypto.Base64Url(Encoding.UTF8.GetBytes(cipher));

                    return TokenWire.Build("f", keyId, payload);
                }

                case TokenType.Encrypted:
                {
                    var ct   = AesGcmBc.Encrypt(derived, Encoding.UTF8.GetBytes(fp.Plaintext ?? ""));
                    var blob = AesGcmBc.Pack(ct);
                    return TokenWire.Build("e", keyId, Crypto.Base64Url(blob));
                }

                default:
                    throw new RpcException(new Status(StatusCode.InvalidArgument, $"Unsupported TokenType: {type}"));
            }
        }

        /// <summary>
        /// Versucht, ein Token zurückzuführen (Store → FPE/Encrypted).
        /// </summary>
        private bool TryDetokenizeOne(TokenizedField item, Context ctx, string keyId, out string plaintext)
        {
            plaintext = null;

            // 1) Store-Hit?
            if (store.TryGet(item.Token, out var rec))
            {
                plaintext = rec.Plaintext;
                return true;
            }

            // 2) Token parsen (um Typ/Payload zu kennen)
            if (!TokenWire.TryParse(item.Token, out var typeTag, out _, out var payload))
                return false;

            // 3) Kryptografische Rückführung je nach Typ
            if (typeTag == "f")
            {
                if (fpe == null) return false;

                var tenant    = ctx?.TenantId ?? "";
                var masterKey = keys.GetKey(tenant, keyId);
                var tweak     = ctx?.Tweak?.ToByteArray() ?? Array.Empty<byte>();
                var info      = Encoding.UTF8.GetBytes($"ctx|tenant={tenant}|kid={keyId}|field={item.Field}");
                var derived   = Crypto.Hkdf(masterKey, tweak, info, AesKeyLen);

                var alphabet  = InferAlphabetFromField(item.Field);
                var cipher    = (alphabet == Alphabets.Digits && payload.All(char.IsDigit))
                                ? payload
                                : Encoding.UTF8.GetString(Crypto.FromBase64Url(payload));

                plaintext = fpe.Decrypt(cipher, derived, tweak, alphabet);
                return true;
            }

            if (typeTag == "e")
            {
                var tenant    = ctx?.TenantId ?? "";
                var masterKey = keys.GetKey(tenant, keyId);
                var tweak     = ctx?.Tweak?.ToByteArray() ?? Array.Empty<byte>();
                var info      = Encoding.UTF8.GetBytes($"ctx|tenant={tenant}|kid={keyId}|field={item.Field}");
                var derived   = Crypto.Hkdf(masterKey, tweak, info, AesKeyLen);

                var blob   = Crypto.FromBase64Url(payload);
                AesGcmBc.Unpack(blob, out var nonce, out var tag, out var ciphertext);
                var ptBytes = AesGcmBc.Decrypt(derived, nonce, ciphertext, tag);
                plaintext = Encoding.UTF8.GetString(ptBytes);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Erzeugt bei Bedarf eine deterministische, formatierte Sicht (<see cref="FormatMode.Masked"/>)
        /// und hängt sie als Suffix <c>~{view}</c> an den Token an.
        /// </summary>
        private static string ApplyMaskedViewIfRequested(string token, FieldPayload fp, byte[] derived)
        {
            if (fp.FormatMode == FormatMode.Masked && !string.IsNullOrEmpty(fp.FormatMask))
            {
                var seed = Crypto.Hkdf(derived, null, Encoding.UTF8.GetBytes("view/mask:" + (fp.Plaintext ?? "")), 32);
                var view = FormatShim.DeterministicMaskedView(fp.FormatMask, seed);
                return $"{token}~{view}";
            }
            return token;
        }
    }
}
